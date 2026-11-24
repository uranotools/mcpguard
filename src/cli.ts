#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import type { SecurityPolicy } from './types.js';
import { HttpAuthRequiredError } from './adapters/http.js';
import { createTransportAdapter } from './adapters/index.js';
import { runOAuthBrowserLogin } from './auth/oauth.js';
import {
  getBoolFlag,
  getListFlag,
  getStringFlag,
  parseCliArgs,
  parseKeyValuePairs,
  type ParsedCliArgs,
} from './cli/args.js';
import { McpGuardPipeline } from './cli/pipeline.js';
import { McpConnector } from './core/connector.js';
import { createContext, NATIVE_CONTEXT_KEYS } from './core/context.js';
import {
  buildToolForm,
  coerceFieldValue,
  setNestedValue,
  validateFormValues,
} from './core/schemaForm.js';
import {
  getProviderPreset,
  listProviderPresets,
  resolveAiProvider,
  fillToolWithAi,
  streamFieldWithAi,
} from './providers/index.js';
import {
  isBlockedByPolicy,
  renderMarkdownSecurityReport,
  scanOutgoingArgsForSecrets,
  scanOutputForLeaksAndInjection,
} from './security/index.js';
import {
  ansi,
  formatAuditSuiteTerminal,
  formatSecurityReportTerminal,
  playUranoBannerAnimated,
  ProgressRenderer,
  promptConfirm,
  renderUranoBanner,
  runInteractiveFormWizard,
  startInteractiveShell,
  type BannerAccent,
  type BannerStyle,
} from './ui/index.js';

const VERSION = '0.1.0';

export async function runCli(argv: string[], baseDir?: string): Promise<number> {
  const parsed = parseCliArgs(argv);
  const [cmd, ...rest] = parsed.positionals;

  if (getBoolFlag(parsed.flags, 'version')) {
    console.log(`mcpguard v${VERSION}`);
    return 0;
  }

  const pipeline = new McpGuardPipeline(baseDir);

  // Launch interactive internal CLI shell with banner when --iniciar / --start / shell / repl is passed
  const wantsShell =
    getBoolFlag(parsed.flags, 'iniciar') ||
    getBoolFlag(parsed.flags, 'start') ||
    cmd === 'iniciar' ||
    cmd === 'shell' ||
    cmd === 'repl';

  if (wantsShell) {
    return startInteractiveShell({
      version: VERSION,
      baseDir,
      accent: (getStringFlag(parsed.flags, 'accent') as BannerAccent | undefined) ?? 'amber',
      style: (getStringFlag(parsed.flags, 'style') as BannerStyle | undefined) ?? 'block',
      animate: getBoolFlag(parsed.flags, 'animate'),
      executeCommand: (subArgv) => runCli(subArgv, baseDir),
      getCompletableNames: () => pipeline.registry.listServers().map((s) => s.name),
    });
  }

  if (!cmd || cmd === 'help' || getBoolFlag(parsed.flags, 'help')) {
    printHelp();
    return 0;
  }

  try {
    switch (cmd) {
      case 'install':
        return await handleInstall(pipeline, rest, parsed);
      case 'scan':
        return await handleScan(pipeline, rest, parsed);
      case 'report':
        return await handleReport(pipeline, rest, parsed);
      case 'audit':
        return await handleAudit(pipeline, rest, parsed);
      case 'trust':
        return await handleTrust(pipeline, rest, parsed);
      case 'provider':
        return await handleProvider(pipeline, rest, parsed);
      case 'auth':
        return await handleAuth(pipeline, rest, parsed);
      case 'inspect':
        return await handleInspect(pipeline, rest, parsed);
      case 'doctor':
        return await handleDoctor(pipeline, parsed);
      case 'preset':
        return await handlePreset(pipeline, rest, parsed);
      case 'history':
        return await handleHistory(pipeline, parsed);
      case 'export':
        return await handleExport(pipeline, parsed);
      case 'servers':
      case 'list':
        return handleListServers(pipeline, parsed);
      case 'banner': {
        const style = (getStringFlag(parsed.flags, 'style') as BannerStyle | undefined) ?? 'block';
        const accent = (getStringFlag(parsed.flags, 'accent') as BannerAccent | undefined) ?? 'amber';
        const bannerOpts = {
          product: 'mcpguard',
          version: VERSION,
          tagline: 'Interactive MCP CLI // AI Flags // Security Shield',
          url: 'https://github.com/uranotools/mcpguard',
          style,
          accent,
        };
        if (getBoolFlag(parsed.flags, 'animate')) {
          await playUranoBannerAnimated(bannerOpts);
        } else {
          console.log(renderUranoBanner(bannerOpts));
        }
        return 0;
      }
      default:
        return await handleInvoke(pipeline, cmd, rest, parsed);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (getBoolFlag(parsed.flags, 'json')) {
      console.error(JSON.stringify({ error: msg }));
    } else {
      console.error(`${ansi.red('Error:')} ${msg}`);
    }
    return 1;
  }
}

async function handleInstall(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const target = rest[0];
  if (!target) throw new Error('Usage: mcpguard install <url | "stdio command"> [--name <alias>]');

  const resolved = pipeline.resolveTarget(target, parsed.flags);
  let secret = resolved.secret;

  // Attempt discovery; if 401 and HTTP, launch OAuth 2.1 browser flow automatically!
  let connector = new McpConnector(createTransportAdapter(resolved.config, { secret }));
  try {
    await connector.discover();
  } catch (err) {
    await connector.disconnect();
    const needsOAuth =
      err instanceof HttpAuthRequiredError ||
      resolved.config.auth === 'oauth';

    if (needsOAuth && (resolved.config.adapter === 'http' || resolved.config.adapter === 'sse')) {
      console.log(ansi.cyan('▸ Server requires authentication. Starting OAuth 2.1 browser login...'));
      const wwwAuth = err instanceof HttpAuthRequiredError ? err.wwwAuthenticate : undefined;
      const oauthRes = await runOAuthBrowserLogin({
        mcpUrl: resolved.config.target,
        wwwAuthenticate: wwwAuth,
        scopes: getListFlag(parsed.flags, 'scope'),
        noBrowser: getBoolFlag(parsed.flags, 'no-browser'),
        onAuthUrl: (u) => console.log(`  Open URL: ${ansi.blue(u)}`),
      });
      secret = oauthRes.tokens.access_token;
      resolved.config.auth = 'oauth';
      resolved.config.oauth = {
        authorizationEndpoint: oauthRes.metadata.authorization_endpoint,
        tokenEndpoint: oauthRes.metadata.token_endpoint,
        clientId: oauthRes.clientId,
        scopes: getListFlag(parsed.flags, 'scope'),
        redirectUri: oauthRes.redirectUri,
      };
    } else {
      throw err;
    }
  } finally {
    await connector.disconnect();
  }

  // Run full VirusTotal-style security scan before persisting
  const scanRes = await pipeline.connectAndScan(target, {
    ...parsed,
    flags: {
      ...parsed.flags,
      ...(resolved.config.auth ? { auth: resolved.config.auth } : {}),
      ...(secret ? { token: secret } : {}),
    },
  });
  await scanRes.connector?.disconnect();

  const policy =
    (getStringFlag(parsed.flags, 'security') as SecurityPolicy | undefined) ??
    pipeline.registry.load().securityPolicy;

  if (!getBoolFlag(parsed.flags, 'json')) {
    console.log(formatSecurityReportTerminal(scanRes.report));
  }

  if (isBlockedByPolicy(scanRes.report.verdict, policy)) {
    throw new Error(
      `Installation blocked by security policy "${policy}" (verdict: ${scanRes.report.verdict}, score: ${scanRes.report.score}/100).`,
    );
  }

  if (
    scanRes.report.verdict === 'SUSPICIOUS' &&
    policy !== 'off' &&
    !getBoolFlag(parsed.flags, 'yes')
  ) {
    const ok = await promptConfirm('Security verdict is SUSPICIOUS. Continue installing?', false);
    if (!ok) {
      console.log('Installation cancelled.');
      return 1;
    }
  }

  if (secret) {
    const secretRef = `server:${resolved.config.name}`;
    pipeline.registry.vault.set(secretRef, secret);
    resolved.config.secretRef = secretRef;
  }

  resolved.config.lastScannedAt = scanRes.report.timestamp;
  resolved.config.lastVerdict = scanRes.report.verdict;
  pipeline.registry.upsertServer(resolved.config);

  // Pin SHA-256 tool hashes in trust.lock.json for Rug Pull protection
  pipeline.trustLock.pin(
    resolved.config.name,
    resolved.config.target,
    scanRes.discovery?.tools ?? [],
  );

  if (getBoolFlag(parsed.flags, 'json')) {
    console.log(JSON.stringify({ installed: resolved.config, report: scanRes.report }, null, 2));
  } else {
    console.log(
      `\n${ansi.green('✓')} Installed MCP "${ansi.bold(resolved.config.name)}" (${scanRes.discovery?.tools.length ?? 0} tool(s) pinned in trust.lock.json).`,
    );
  }
  return 0;
}

async function handleScan(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const scanAll = getBoolFlag(parsed.flags, 'all');
  const targets = scanAll
    ? pipeline.registry.listServers().map((s) => s.name)
    : rest[0]
      ? [rest[0]]
      : [];

  if (targets.length === 0) {
    throw new Error('Usage: mcpguard scan <url | path | "stdio cmd" | mcp_name | --all> [--deep] [--probe] [--json]');
  }

  const isJson = getBoolFlag(parsed.flags, 'json');
  const isVerbose = getBoolFlag(parsed.flags, 'verbose') || getBoolFlag(parsed.flags, 'live');
  const watchRaw = parsed.flags.watch;
  const watchSeconds =
    watchRaw === true ? 15 : typeof watchRaw === 'string' ? Math.max(3, Number(watchRaw) || 15) : 0;

  const runOnce = async () => {
    const reports = [];
    for (const t of targets) {
      if (!isJson) {
        console.log(`${ansi.cyan('▸')} Scanning ${ansi.bold(t)}...`);
      }
      const res = await pipeline.connectAndScan(t, parsed, {
        skipDiscoveryIfLocalOnly: true,
        onEngineStart: isJson
          ? undefined
          : (idx, total, name) => {
              process.stderr.write(`  ${ansi.dim(`[${idx}/${total}]`)} ${name}... `);
            },
        onEngineDone: isJson
          ? undefined
          : (_idx, _total, engRes) => {
              const tag =
                engRes.status === 'pass'
                  ? ansi.green('OK')
                  : engRes.status === 'warn'
                    ? ansi.yellow('WARN')
                    : engRes.status === 'fail'
                      ? ansi.red('FAIL')
                      : ansi.gray('SKIP');
              process.stderr.write(`${tag} ${ansi.dim(`(${engRes.durationMs ?? 0}ms)`)}\n`);
              if (isVerbose) {
                process.stderr.write(`      ${ansi.dim(engRes.summary)}\n`);
                for (const f of engRes.findings) {
                  process.stderr.write(
                    `      ${ansi.yellow('•')} [${f.severity.toUpperCase()}] ${f.title}\n`,
                  );
                }
              }
            },
      });
      await res.connector?.disconnect();
      reports.push(res.report);
      if (!isJson) {
        console.log('');
        console.log(
          formatSecurityReportTerminal(res.report, {
            detail: getBoolFlag(parsed.flags, 'detail'),
            group: getStringFlag(parsed.flags, 'group'),
            section: getStringFlag(parsed.flags, 'section'),
          }),
        );
      }
    }
    if (isJson) {
      console.log(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2));
    }
    return reports;
  };

  const firstReports = await runOnce();

  if (watchSeconds > 0 && !isJson) {
    console.log(ansi.cyan(`\n▸ Watch mode active: re-scanning every ${watchSeconds}s (Ctrl+C to stop)...`));
    await new Promise<void>((resolve) => {
      const timer = setInterval(async () => {
        console.log(ansi.dim(`\n── Watch refresh @ ${new Date().toISOString()} ──`));
        await runOnce().catch((e) => console.error(ansi.red(String(e))));
      }, watchSeconds * 1000);
      process.once('SIGINT', () => {
        clearInterval(timer);
        resolve();
      });
    });
  }

  const hasMalicious = firstReports.some((r) => r.verdict === 'MALICIOUS');
  return hasMalicious ? 2 : 0;
}

async function handleReport(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const target = rest[0];
  if (!target) {
    throw new Error('Usage: mcpguard report <target> [--format terminal|md|json] [--out <file>]');
  }

  const res = await pipeline.connectAndScan(target, parsed, { skipDiscoveryIfLocalOnly: true });
  await res.connector?.disconnect();

  const fmt = (getStringFlag(parsed.flags, 'format') ?? 'md').toLowerCase();
  const content =
    fmt === 'json'
      ? JSON.stringify(res.report, null, 2)
      : fmt === 'terminal'
        ? formatSecurityReportTerminal(res.report)
        : renderMarkdownSecurityReport(res.report);

  const outFile = getStringFlag(parsed.flags, 'out');
  if (outFile) {
    writeFileSync(outFile, content, 'utf8');
    console.log(`${ansi.green('✓')} Report written to ${outFile}`);
  } else {
    console.log(content);
  }
  return 0;
}

async function handleAudit(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const target = rest[0];
  if (!target) {
    throw new Error('Usage: mcpguard audit <target> [--group owasp-mcp|privacy|<custom>] [--plugin <file>]');
  }

  const { ctx, connector } = await pipeline.connectAndScan(target, parsed, {
    skipDiscoveryIfLocalOnly: true,
  });
  await connector?.disconnect();

  const groupId = getStringFlag(parsed.flags, 'group');
  const suites = groupId
    ? [pipeline.auditRunner.get(groupId)].filter((s): s is NonNullable<typeof s> => Boolean(s))
    : pipeline.auditRunner.list();

  if (suites.length === 0) {
    throw new Error(
      `Audit group "${groupId}" not found. Available: ${pipeline.auditRunner.list().map((s) => s.id).join(', ')}`,
    );
  }

  const reports = [];
  for (const s of suites) {
    const rep = await pipeline.auditRunner.runSuite(s, ctx);
    reports.push(rep);
    if (!getBoolFlag(parsed.flags, 'json')) {
      console.log(formatAuditSuiteTerminal(rep));
    }
  }

  if (getBoolFlag(parsed.flags, 'json')) {
    console.log(JSON.stringify({ runId: ctx.runId, audits: reports }, null, 2));
  }

  return reports.some((r) => r.failed > 0) ? 1 : 0;
}

async function handleTrust(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const [action, name] = rest;
  if (!action || !name) {
    throw new Error('Usage: mcpguard trust <diff|approve> <mcp_name>');
  }

  const resolved = pipeline.resolveTarget(name, parsed.flags);
  const connector = new McpConnector(createTransportAdapter(resolved.config, { secret: resolved.secret }));
  try {
    const disc = await connector.discover();
    if (action === 'approve') {
      pipeline.trustLock.pin(name, resolved.config.target, disc.tools);
      console.log(`${ansi.green('✓')} Updated SHA-256 trust lock for "${name}" (${disc.tools.length} tools).`);
      return 0;
    }
    const diff = pipeline.trustLock.diff(name, disc.tools);
    if (getBoolFlag(parsed.flags, 'json')) {
      console.log(JSON.stringify(diff, null, 2));
    } else if (!diff.hasChanges) {
      console.log(`${ansi.green('✓')} No schema drift detected for "${name}".`);
    } else {
      console.log(ansi.yellow(`Schema drift detected for "${name}":`));
      if (diff.added.length) console.log(`  Added:   ${diff.added.join(', ')}`);
      if (diff.removed.length) console.log(`  Removed: ${diff.removed.join(', ')}`);
      for (const ch of diff.changed) {
        console.log(`  Changed: ${ansi.bold(ch.name)} (${ch.previousHash.slice(0, 10)} → ${ch.currentHash.slice(0, 10)})`);
      }
    }
    return 0;
  } finally {
    await connector.disconnect();
  }
}

async function handleProvider(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const [action, id] = rest;

  if (!action || action === 'list') {
    const { defaultProvider, providers } = pipeline.registry.listProviders();
    if (getBoolFlag(parsed.flags, 'json')) {
      console.log(JSON.stringify({ defaultProvider, installed: providers, catalog: listProviderPresets() }, null, 2));
      return 0;
    }
    console.log(ansi.bold('Configured AI Providers:'));
    if (providers.length === 0) {
      console.log('  (none configured yet)');
    } else {
      for (const p of providers) {
        const star = p.id === defaultProvider ? ansi.green(' [default]') : '';
        console.log(`  • ${ansi.bold(p.id)}${star} — ${p.name} (${p.model}) @ ${ansi.dim(p.baseUrl)}`);
      }
    }
    console.log('\n' + ansi.bold('Available Catalog Presets:'));
    for (const preset of listProviderPresets()) {
      console.log(`  • ${ansi.cyan(preset.id.padEnd(13))} ${preset.name} (default: ${preset.defaultModel})`);
    }
    return 0;
  }

  if (action === 'add') {
    if (!id) throw new Error('Usage: mcpguard provider add <openrouter|huggingface|openai|anthropic|deepseek|alibaba|gemini|ollama|custom> [--api-key <key>] [--model <m>] [--default]');
    const preset = getProviderPreset(id);
    const baseUrl = getStringFlag(parsed.flags, 'base-url') ?? preset?.baseUrl;
    if (!baseUrl) {
      throw new Error(`Unknown provider "${id}". Pass --base-url for a custom OpenAI-compatible provider.`);
    }
    const model = getStringFlag(parsed.flags, 'model') ?? preset?.defaultModel ?? 'gpt-4o-mini';
    const apiKey =
      getStringFlag(parsed.flags, 'api-key') ??
      (preset?.envVar ? process.env[preset.envVar] : undefined);

    const secretRef = apiKey ? `provider:${id}` : undefined;
    if (secretRef && apiKey) {
      pipeline.registry.vault.set(secretRef, apiKey);
    }

    pipeline.registry.upsertProvider(
      {
        id,
        name: preset?.name ?? id,
        driver: preset?.driver ?? 'openai-compat',
        baseUrl,
        model,
        secretRef,
        envVar: preset?.envVar,
        extraHeaders: preset?.extraHeaders,
        addedAt: new Date().toISOString(),
      },
      getBoolFlag(parsed.flags, 'default'),
    );
    console.log(`${ansi.green('✓')} Provider "${ansi.bold(id)}" configured (model: ${model}).`);
    return 0;
  }

  if (action === 'use') {
    if (!id || !pipeline.registry.setDefaultProvider(id)) {
      throw new Error(`Provider "${id ?? ''}" is not configured.`);
    }
    console.log(`${ansi.green('✓')} Default AI provider set to "${id}".`);
    return 0;
  }

  if (action === 'remove') {
    if (!id || !pipeline.registry.removeProvider(id)) {
      throw new Error(`Provider "${id ?? ''}" is not configured.`);
    }
    console.log(`${ansi.green('✓')} Removed provider "${id}".`);
    return 0;
  }

  if (action === 'test') {
    const adapter = resolveAiProvider(pipeline.registry, id);
    if (!adapter) throw new Error('No AI provider configured.');
    const check = await adapter.healthCheck();
    if (getBoolFlag(parsed.flags, 'json')) {
      console.log(JSON.stringify({ provider: adapter.id, ...check }, null, 2));
    } else if (check.ok) {
      console.log(`${ansi.green('✓')} Provider "${adapter.id}" reachable (${check.latencyMs}ms).`);
    } else {
      console.log(`${ansi.red('✗')} Provider "${adapter.id}" failed: ${check.error}`);
    }
    return check.ok ? 0 : 1;
  }

  throw new Error(`Unknown provider subcommand "${action}".`);
}

async function handleAuth(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const [action, name] = rest;
  if (!action || !name) throw new Error('Usage: mcpguard auth <login|status|logout> <mcp_name>');
  const server = pipeline.registry.getServer(name);
  if (!server) throw new Error(`MCP server "${name}" is not installed.`);

  if (action === 'status') {
    const hasToken = server.secretRef ? Boolean(pipeline.registry.vault.get(server.secretRef)) : false;
    console.log(JSON.stringify({ name, auth: server.auth ?? 'none', authenticated: hasToken }, null, 2));
    return 0;
  }

  if (action === 'logout') {
    if (server.secretRef) pipeline.registry.vault.delete(server.secretRef);
    console.log(`${ansi.green('✓')} Cleared stored credentials for "${name}".`);
    return 0;
  }

  if (action === 'login') {
    const res = await runOAuthBrowserLogin({
      mcpUrl: server.target,
      scopes: server.oauth?.scopes ?? getListFlag(parsed.flags, 'scope'),
      noBrowser: getBoolFlag(parsed.flags, 'no-browser'),
      onAuthUrl: (u) => console.log(`  Open URL: ${ansi.blue(u)}`),
    });
    const ref = server.secretRef ?? `server:${name}`;
    pipeline.registry.vault.set(ref, res.tokens.access_token);
    server.secretRef = ref;
    server.auth = 'oauth';
    pipeline.registry.upsertServer(server);
    console.log(`${ansi.green('✓')} Logged into "${name}".`);
    return 0;
  }

  throw new Error(`Unknown auth action "${action}".`);
}

async function handleInspect(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const [name, toolName] = rest;
  if (!name) throw new Error('Usage: mcpguard inspect <mcp_name> [tool_name]');
  const resolved = pipeline.resolveTarget(name, parsed.flags);
  const connector = new McpConnector(createTransportAdapter(resolved.config, { secret: resolved.secret }));
  try {
    const disc = await connector.discover();
    if (!toolName) {
      if (getBoolFlag(parsed.flags, 'json')) {
        console.log(JSON.stringify(disc, null, 2));
      } else {
        console.log(ansi.bold(`${disc.serverInfo.name} (${disc.tools.length} tools):`));
        for (const t of disc.tools) {
          const form = buildToolForm(t);
          console.log(`  • ${ansi.cyan(t.name)} — ${t.description ?? ansi.dim('(no description)')}`);
          for (const s of form.steps) {
            console.log(`      step${s.stepIndex}: ${s.name} (${s.type}${s.required ? ', required' : ''})`);
          }
        }
      }
      return 0;
    }

    const { tool, form } = await connector.getToolForm(toolName);
    if (getBoolFlag(parsed.flags, 'json')) {
      console.log(JSON.stringify({ tool, form }, null, 2));
    } else {
      console.log(ansi.bold(`${tool.name}:`), tool.description ?? '');
      for (const sec of form.sections) {
        console.log(`\n  ${ansi.blue(`[${sec.name}]`)}`);
        for (const s of sec.fields) {
          console.log(`    step${s.stepIndex}: --${s.name} <${s.type}>${s.required ? ' *' : ''} ${ansi.dim(s.description ?? '')}`);
        }
      }
    }
    return 0;
  } finally {
    await connector.disconnect();
  }
}

async function handleDoctor(pipeline: McpGuardPipeline, parsed: ParsedCliArgs): Promise<number> {
  const servers = pipeline.registry.listServers();
  const { defaultProvider, providers } = pipeline.registry.listProviders();
  const diag = {
    nodeVersion: process.version,
    configPath: pipeline.registry.configPath,
    trustLockPath: pipeline.trustLock.filePath,
    securityPolicy: pipeline.registry.load().securityPolicy,
    installedServers: servers.length,
    configuredProviders: providers.length,
    defaultProvider: defaultProvider ?? null,
    vtEnabled: Boolean(process.env.VT_API_KEY),
  };
  if (getBoolFlag(parsed.flags, 'json')) {
    console.log(JSON.stringify(diag, null, 2));
  } else {
    console.log(ansi.bold('MCPGuard Doctor'));
    for (const [k, v] of Object.entries(diag)) {
      console.log(`  ${k.padEnd(22)} ${ansi.cyan(String(v))}`);
    }
  }
  return 0;
}

async function handlePreset(
  pipeline: McpGuardPipeline,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const [action, alias] = rest;
  if (!action || action === 'list') {
    const list = pipeline.registry.listPresets();
    if (getBoolFlag(parsed.flags, 'json')) console.log(JSON.stringify(list, null, 2));
    else if (list.length === 0) console.log('(no saved presets)');
    else list.forEach((p) => console.log(`  • ${ansi.bold(p.alias)} → ${p.mcpName} ${p.toolName}`));
    return 0;
  }
  if (action === 'delete' && alias) {
    pipeline.registry.removePreset(alias);
    console.log(`${ansi.green('✓')} Deleted preset "${alias}".`);
    return 0;
  }
  throw new Error('Usage: mcpguard preset <list|delete <alias>>');
}

async function handleHistory(pipeline: McpGuardPipeline, parsed: ParsedCliArgs): Promise<number> {
  const entries = pipeline.registry.listHistory();
  if (getBoolFlag(parsed.flags, 'json')) {
    console.log(JSON.stringify(entries, null, 2));
  } else if (entries.length === 0) {
    console.log('(no invocation history yet)');
  } else {
    for (const e of entries.slice(0, 20)) {
      const icon = e.ok ? ansi.green('✓') : ansi.red('✗');
      console.log(`  ${icon} [${e.id.slice(0, 8)}] ${e.mcpName} ${ansi.bold(e.toolName)} (${e.durationMs}ms) ${ansi.dim(e.timestamp)}`);
    }
  }
  return 0;
}

async function handleExport(pipeline: McpGuardPipeline, parsed: ParsedCliArgs): Promise<number> {
  const target = getStringFlag(parsed.flags, 'target') ?? 'claude';
  const servers = pipeline.registry.listServers();
  const mcpServers: Record<string, unknown> = {};
  for (const s of servers) {
    if (s.adapter === 'stdio') {
      mcpServers[s.name] = { command: s.target, args: s.args ?? [], env: s.env ?? {} };
    } else {
      mcpServers[s.name] = { url: s.target, headers: s.headers ?? {} };
    }
  }
  console.log(JSON.stringify({ target, mcpServers }, null, 2));
  return 0;
}

function handleListServers(pipeline: McpGuardPipeline, parsed: ParsedCliArgs): number {
  const servers = pipeline.registry.listServers();
  if (getBoolFlag(parsed.flags, 'json')) {
    console.log(JSON.stringify(servers, null, 2));
  } else if (servers.length === 0) {
    console.log('(no MCP servers installed — run "mcpguard install <url|cmd>")');
  } else {
    for (const s of servers) {
      console.log(`  • ${ansi.bold(s.name)} [${s.adapter}] ${ansi.dim(s.target)} ${s.lastVerdict ? `(${s.lastVerdict})` : ''}`);
    }
  }
  return 0;
}

async function handleInvoke(
  pipeline: McpGuardPipeline,
  mcpName: string,
  rest: string[],
  parsed: ParsedCliArgs,
): Promise<number> {
  const action = rest[0] ?? 'list';
  const resolved = pipeline.resolveTarget(mcpName, parsed.flags);
  const ctx = createContext({ [NATIVE_CONTEXT_KEYS.CLI_FLAGS]: parsed.flags });
  const connector = new McpConnector(
    createTransportAdapter(resolved.config, { secret: resolved.secret }),
    ctx,
  );

  try {
    const disc = await connector.discover();

    // Rug Pull check on registered servers before executing anything
    const policy =
      (getStringFlag(parsed.flags, 'security') as SecurityPolicy | undefined) ??
      pipeline.registry.load().securityPolicy;
    if (resolved.isRegistered && policy !== 'off') {
      const diff = pipeline.trustLock.diff(resolved.config.name, disc.tools);
      if (diff.changed.length > 0 && !getBoolFlag(parsed.flags, 'trust-update')) {
        throw new Error(
          `Possible Rug Pull detected on "${mcpName}": tool(s) mutated [${diff.changed.map((c) => c.name).join(', ')}]. Run "mcpguard trust diff ${mcpName}" or pass --trust-update.`,
        );
      }
    }

    if (action === 'list') {
      if (getBoolFlag(parsed.flags, 'json')) {
        console.log(JSON.stringify(disc.tools, null, 2));
      } else {
        console.log(ansi.bold(`${disc.serverInfo.name} — ${disc.tools.length} action(s):`));
        for (const t of disc.tools) {
          console.log(`  • ${ansi.cyan(t.name)} — ${t.description ?? ''}`);
        }
      }
      return 0;
    }

    const { tool, form } = await connector.getToolForm(action);
    let payload: Record<string, unknown> = {};

    // Load preset if specified
    const presetAlias = getStringFlag(parsed.flags, 'preset');
    if (presetAlias) {
      const preset = pipeline.registry.getPreset(presetAlias);
      if (!preset) throw new Error(`Preset "${presetAlias}" not found.`);
      payload = structuredClone(preset.args);
    }

    // Apply direct CLI flags matching form fields
    for (const step of form.steps) {
      const flagVal = parsed.flags[step.name];
      if (flagVal !== undefined) {
        setNestedValue(
          payload,
          step.path,
          typeof flagVal === 'string' ? coerceFieldValue(flagVal, step) : flagVal,
        );
      }
    }

    const aiProvider = resolveAiProvider(
      pipeline.registry,
      getStringFlag(parsed.flags, 'ai-provider'),
      getStringFlag(parsed.flags, 'ai-model'),
    );

    // Full-form AI fill (--ai "<prompt>")
    const aiPrompt = getStringFlag(parsed.flags, 'ai');
    if (aiPrompt) {
      if (!aiProvider) throw new Error('No AI provider configured. Run: mcpguard provider add <id>');
      const generated = await fillToolWithAi({
        provider: aiProvider,
        tool,
        instruction: aiPrompt,
        existingValues: payload,
        model: getStringFlag(parsed.flags, 'ai-model'),
      });
      payload = { ...generated, ...payload };
    }

    // Per-field streaming AI fill (--ai-field field="instruction")
    const aiFields = parseKeyValuePairs(getListFlag(parsed.flags, 'ai-field'), '=');
    for (const [fieldName, instruction] of Object.entries(aiFields)) {
      const step = form.steps.find((s) => s.name === fieldName);
      if (!step) continue;
      if (!aiProvider) throw new Error('No AI provider configured. Run: mcpguard provider add <id>');
      if (!getBoolFlag(parsed.flags, 'json')) {
        process.stderr.write(`${ansi.magenta(`[AI:${fieldName}]`)} `);
      }
      const val = await streamFieldWithAi({
        provider: aiProvider,
        tool,
        field: step,
        instruction,
        currentValues: payload,
        model: getStringFlag(parsed.flags, 'ai-model'),
        onChunk: (d) => {
          if (!getBoolFlag(parsed.flags, 'json')) process.stderr.write(d);
        },
      });
      if (!getBoolFlag(parsed.flags, 'json')) process.stderr.write('\n');
      setNestedValue(payload, step.path, coerceFieldValue(val, step));
    }

    // Interactive wizard (-i / --interactive)
    if (getBoolFlag(parsed.flags, 'interactive')) {
      const wiz = await runInteractiveFormWizard({
        tool,
        form,
        initialValues: payload,
        aiProvider,
        aiModel: getStringFlag(parsed.flags, 'ai-model'),
      });
      if (wiz.cancelled) return 0;
      payload = wiz.values;
    }

    // Validate required fields
    const validationErrors = validateFormValues(form, payload);
    if (validationErrors.length > 0) {
      throw new Error(`Validation failed:\n  - ${validationErrors.join('\n  - ')}`);
    }

    // Runtime Guard: check outgoing args for accidental secret leaks
    if (policy !== 'off') {
      const secCheck = scanOutgoingArgsForSecrets(payload);
      if (secCheck.hasSecrets) {
        if (policy === 'strict') {
          throw new Error(
            `Blocked by runtime guard: outgoing payload contains secret(s): ${secCheck.findings.map((f) => f.title).join(', ')}`,
          );
        }
        console.error(ansi.yellow(`⚠ Runtime Guard: ${secCheck.findings.length} potential secret(s) detected in outgoing args.`));
      }
    }

    // Save preset if requested
    const savePresetAlias = getStringFlag(parsed.flags, 'save-preset');
    if (savePresetAlias) {
      pipeline.registry.savePreset({
        alias: savePresetAlias,
        mcpName,
        toolName: tool.name,
        args: payload,
        createdAt: new Date().toISOString(),
      });
    }

    if (getBoolFlag(parsed.flags, 'dry-run')) {
      console.log(JSON.stringify({ dryRun: true, mcp: mcpName, tool: tool.name, args: payload }, null, 2));
      return 0;
    }

    const progressMode = (getStringFlag(parsed.flags, 'progress') ?? 'bar') as 'bar' | 'steps' | 'quiet';
    const renderer = new ProgressRenderer(getBoolFlag(parsed.flags, 'json') ? 'quiet' : progressMode);

    const start = Date.now();
    const result = await connector.callTool(tool.name, payload, {
      onProgress: (ev) => renderer.onProgress(ev),
      onLog: (ev) => renderer.onLog(ev),
    });
    renderer.done();

    // Runtime Guard: scan tool output for indirect prompt injection or leaked secrets
    const outFindings = policy !== 'off' ? scanOutputForLeaksAndInjection(result) : [];

    pipeline.registry.appendHistory({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      mcpName,
      toolName: tool.name,
      args: scanOutgoingArgsForSecrets(payload).maskedPayload,
      durationMs: Date.now() - start,
      ok: !result.isError,
    });

    if (getBoolFlag(parsed.flags, 'json')) {
      console.log(JSON.stringify({ result, runtimeWarnings: outFindings }, null, 2));
    } else {
      for (const item of result.content) {
        if (item.text) console.log(item.text);
        else console.log(JSON.stringify(item, null, 2));
      }
      if (outFindings.length > 0) {
        console.error(
          ansi.yellow(`\n⚠ Runtime Guard flagged ${outFindings.length} issue(s) in tool output: ${outFindings.map((f) => f.title).join('; ')}`),
        );
      }
    }
    return result.isError ? 1 : 0;
  } finally {
    await connector.disconnect();
  }
}

function printHelp(): void {
  console.log('');
  console.log(
    renderUranoBanner({
      product: 'mcpguard',
      version: VERSION,
      tagline: 'Interactive MCP CLI • AI Flags • Security Shield',
      url: 'https://github.com/uranotools/mcpguard',
    }),
  );
  console.log(`
${ansi.bold('Usage:')}
  mcpguard install <url | "stdio cmd"> [--name <alias>] [--auth auto|oauth|bearer|hmac] [--security warn|strict|off]
  mcpguard scan <url | path | "stdio cmd" | mcp | --all> [--detail] [--group <risk>] [--expand-meta] [--only tls,meta,poison] [--section tls|meta|tools|findings] [--verbose] [--watch 15] [--probe] [--deep] [--json]
  mcpguard report <target> [--format md|terminal|json] [--out <file>]
  mcpguard audit <target> [--group owasp-mcp|privacy|<custom>] [--plugin <file>]
  mcpguard trust <diff|approve> <mcp_name>
  mcpguard provider <add|list|use|test|remove> [openrouter|huggingface|openai|anthropic|deepseek|alibaba|gemini|ollama]
  mcpguard auth <login|status|logout> <mcp_name>
  mcpguard <mcp_name> list
  mcpguard <mcp_name> <tool_name> [-i] [--<field> <val>] [--ai "<prompt>"] [--ai-field <f>="<prompt>"] [--dry-run] [--json]
  mcpguard inspect <mcp_name> [tool_name]
  mcpguard doctor | preset | history | export --target claude|cursor|vscode|antigravity
  mcpguard --iniciar [--accent amber|phosphor] [--animate]   (launches internal CLI shell with banner & session globals)
  mcpguard banner [--style block|compact|ascii]
`);
}

// Run when invoked directly as CLI binary
const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('cli.ts'));
if (isMain) {
  runCli(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
