import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { splitCommandLine } from '../adapters/index.js';
import { ansi } from './ansi.js';
import { playUranoBannerAnimated, renderUranoBanner, type BannerAccent, type BannerStyle } from './brand.js';

export interface InteractiveShellOptions {
  version: string;
  baseDir?: string;
  accent?: BannerAccent;
  style?: BannerStyle;
  animate?: boolean;
  executeCommand: (argv: string[]) => Promise<number>;
  getCompletableNames?: () => string[];
}

const BUILTIN_COMMANDS = [
  'install',
  'scan',
  'report',
  'audit',
  'trust',
  'provider',
  'auth',
  'inspect',
  'doctor',
  'preset',
  'history',
  'export',
  'servers',
  'banner',
  'globals',
  'set',
  'unset',
  'clear',
  'help',
  'exit',
  'quit',
];

/**
 * Interactive internal CLI shell (`mcpguard --iniciar` / `mcpguard --start` / `mcpguard shell`).
 * Prints the UranoTools header once and lets the user run commands & persistent global flags
 * (`--security`, `--ai-provider`, `--ai-model`, `--offline`, `--json`, etc.) interactively.
 */
export async function startInteractiveShell(opts: InteractiveShellOptions): Promise<number> {
  const sessionGlobals = new Map<string, string | true>();
  const accent = opts.accent ?? 'amber';
  const style = opts.style ?? 'block';

  const bannerOpts = {
    product: 'mcpguard',
    version: opts.version,
    tagline: 'Interactive MCP CLI • AI Flags • Security Shield',
    url: 'https://github.com/uranotools/mcpguard',
    accent,
    style,
  };

  console.log('');
  if (opts.animate) {
    await playUranoBannerAnimated(bannerOpts, 28);
  } else {
    console.log(renderUranoBanner(bannerOpts));
  }
  console.log('');
  console.log(
    `  ${ansi.muted('Interactive CLI ready. Type any command without "mcpguard" (e.g. "provider list", "doctor", "scan <target>").')}`,
  );
  console.log(
    `  ${ansi.muted('Session globals: "set --security strict", "set --ai-provider openrouter", "globals", "clear", "exit".')}`,
  );
  console.log('');

  const historyPath = join(
    opts.baseDir ?? process.env.MCPGUARD_HOME ?? join(homedir(), '.mcpguard'),
    'shell_history.txt',
  );
  const savedHistory = loadShellHistory(historyPath);

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: Boolean(process.stdin.isTTY),
    historySize: 200,
    removeHistoryDuplicates: true,
    history: savedHistory,
    completer: (line: string): [string[], string] => {
      const candidates = [...BUILTIN_COMMANDS, ...(opts.getCompletableNames?.() ?? [])];
      const hits = candidates.filter((c) => c.startsWith(line));
      return [hits.length ? hits : candidates, line];
    },
  });

  const commandLog = [...savedHistory];

  try {
    while (true) {
      const globalTag =
        sessionGlobals.size > 0
          ? ansi.muted(` [${Array.from(sessionGlobals.keys()).join(' ')}]`)
          : '';
      const promptStr = `${ansi.amber('mcpguard')}${globalTag} ${ansi.bold(ansi.ink('›'))} `;

      let line: string;
      try {
        line = (await rl.question(promptStr)).trim();
      } catch {
        break; // EOF / Ctrl+C
      }

      if (!line) continue;
      recordShellHistory(historyPath, commandLog, line);
      const parsed = splitCommandLine(line);
      const tokens = [parsed.command, ...parsed.args].filter(Boolean);
      const head = tokens[0]?.toLowerCase();

      if (head === 'exit' || head === 'quit' || head === '.exit') {
        console.log(ansi.muted('  Goodbye.'));
        break;
      }

      if (head === 'clear' || head === 'cls') {
        console.clear();
        console.log(renderUranoBanner(bannerOpts));
        console.log('');
        continue;
      }

      if (head === 'globals') {
        if (sessionGlobals.size === 0) {
          console.log(ansi.muted('  (no active session global flags — use "set --security strict")'));
        } else {
          for (const [k, v] of sessionGlobals.entries()) {
            console.log(`  ${ansi.amber(k)} = ${v === true ? 'true' : v}`);
          }
        }
        continue;
      }

      if (head === 'set') {
        const flag = tokens[1];
        if (!flag || !flag.startsWith('--')) {
          console.log(ansi.muted('  Usage: set --<flag> [value]  (e.g. set --security strict, set --offline)'));
          continue;
        }
        const val = tokens[2];
        sessionGlobals.set(flag, val !== undefined ? val : true);
        console.log(`  ${ansi.green('✓')} Global flag ${ansi.bold(flag)} = ${val ?? 'true'}`);
        continue;
      }

      if (head === 'unset') {
        const flag = tokens[1];
        if (flag && sessionGlobals.delete(flag)) {
          console.log(`  ${ansi.green('✓')} Unset global flag ${flag}`);
        } else {
          console.log(ansi.muted('  Usage: unset --<flag>'));
        }
        continue;
      }

      // Strip leading "mcpguard" if user pasted a full command
      const effectiveTokens = head === 'mcpguard' ? tokens.slice(1) : tokens;
      const mergedArgv = mergeSessionGlobals(effectiveTokens, sessionGlobals);

      // Pause shell readline while subcommands run so nested prompts don't corrupt TTY raw mode
      rl.pause();
      try {
        await opts.executeCommand(mergedArgv);
      } finally {
        rl.resume();
      }
      console.log('');
    }
    return 0;
  } finally {
    rl.close();
  }
}

function loadShellHistory(filePath: string): string[] {
  if (!existsSync(filePath)) return [];
  try {
    // Node readline expects newest-first order in `history`
    return readFileSync(filePath, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .slice(0, 200);
  } catch {
    return [];
  }
}

function recordShellHistory(filePath: string, log: string[], line: string): void {
  const idx = log.indexOf(line);
  if (idx >= 0) log.splice(idx, 1);
  log.unshift(line);
  if (log.length > 200) log.length = 200;
  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, log.join('\n') + '\n', 'utf8');
  } catch {
    // Non-fatal
  }
}

export function mergeSessionGlobals(
  argv: string[],
  globals: Map<string, string | true>,
): string[] {
  const out = [...argv];
  for (const [flag, val] of globals.entries()) {
    const alreadySet = argv.some((a) => a === flag || a.startsWith(`${flag}=`));
    if (alreadySet) continue;
    out.push(flag);
    if (val !== true) out.push(val);
  }
  return out;
}
