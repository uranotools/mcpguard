import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCliArgs } from '../src/cli/args.js';
import { runCli } from '../src/cli.js';
import { renderUranoBanner } from '../src/ui/brand.js';
import { mergeSessionGlobals } from '../src/ui/shell.js';

test('parseCliArgs handles flags, equals syntax, short flags, and repeatable flags', () => {
  const parsed = parseCliArgs([
    'crm',
    'register_form',
    '-i',
    '--name',
    'Acme',
    '--ai-field',
    'descripcion=Short pitch',
    '--ai-field',
    'notes=Extra note',
    '--header=X-Org: acme',
    '--dry-run',
  ]);
  assert.deepEqual(parsed.positionals, ['crm', 'register_form']);
  assert.equal(parsed.flags.interactive, true);
  assert.equal(parsed.flags.name, 'Acme');
  assert.equal(parsed.flags['dry-run'], true);
  assert.deepEqual(parsed.flags['ai-field'], ['descripcion=Short pitch', 'notes=Extra note']);
  assert.deepEqual(parsed.flags.header, ['X-Org: acme']);
});

test('runCli manages providers, runs local code scan/report/audit, and executes doctor', async () => {
  const homeDir = mkdtempSync(join(tmpdir(), 'mcpguard-home-'));
  const sampleDir = mkdtempSync(join(tmpdir(), 'mcpguard-sample-'));
  writeFileSync(
    join(sampleDir, 'index.js'),
    'const api = "https://api.github.com/repos";\nconst key = process.env.PORT;\n',
    'utf8',
  );

  // 1. Add and list AI provider
  assert.equal(
    await runCli(['provider', 'add', 'openrouter', '--api-key', 'sk-or-test', '--model', 'deepseek/deepseek-chat', '--default'], homeDir),
    0,
  );
  assert.equal(await runCli(['provider', 'list', '--json'], homeDir), 0);

  // 2. Scan local directory offline
  assert.equal(await runCli(['scan', sampleDir, '--offline', '--json'], homeDir), 0);

  // 3. Generate Markdown + Mermaid report to file
  const reportFile = join(homeDir, 'audit-report.md');
  assert.equal(await runCli(['report', sampleDir, '--offline', '--format', 'md', '--out', reportFile], homeDir), 0);
  const md = readFileSync(reportFile, 'utf8');
  assert.match(md, /# MCPGuard Security & Architecture Report/);
  assert.match(md, /api\.github\.com/);

  // 4. Run built-in privacy audit suite
  assert.equal(await runCli(['audit', sampleDir, '--offline', '--group', 'privacy', '--json'], homeDir), 0);

  // 5. Doctor command
  assert.equal(await runCli(['doctor', '--json'], homeDir), 0);

  // 6. Reusable UranoTools clean calligraphic banner
  const bannerBlock = renderUranoBanner({ product: 'mcpguard', version: '0.1.0', style: 'block', plain: true });
  const bannerAscii = renderUranoBanner({ product: 'urano-guard', version: '1.2.1', style: 'ascii', plain: true });
  assert.match(bannerBlock, /mcpguard v0\.1\.0/);
  assert.match(bannerBlock, /▄ ▀██/);
  assert.match(bannerAscii, /urano-guard v1\.2\.1/);
  assert.match(bannerAscii, /\.====\./);

  // 7. Interactive shell session global flags merger
  const globals = new Map<string, string | true>([
    ['--security', 'strict'],
    ['--offline', true],
  ]);
  assert.deepEqual(mergeSessionGlobals(['scan', './demo'], globals), [
    'scan',
    './demo',
    '--security',
    'strict',
    '--offline',
  ]);
  assert.deepEqual(mergeSessionGlobals(['scan', './demo', '--security', 'warn'], globals), [
    'scan',
    './demo',
    '--security',
    'warn',
    '--offline',
  ]);
});
