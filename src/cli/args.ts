export interface ParsedCliArgs {
  positionals: string[];
  flags: Record<string, string | boolean | string[]>;
}

const REPEATABLE_FLAGS = new Set(['header', 'env', 'ai-field', 'plugin', 'scope', 'threat-feed']);

/**
 * Dependency-free CLI argument parser supporting:
 * --flag value, --flag=value, -i / -y short flags, repeatable flags, and dynamic tool flags.
 */
export function parseCliArgs(argv: string[]): ParsedCliArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean | string[]> = {};

  const setFlag = (key: string, val: string | boolean) => {
    if (REPEATABLE_FLAGS.has(key)) {
      const existing = flags[key];
      const arr = Array.isArray(existing) ? existing : existing ? [String(existing)] : [];
      if (typeof val === 'string') arr.push(val);
      flags[key] = arr;
    } else {
      flags[key] = val;
    }
  };

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (tok.startsWith('--')) {
      const eq = tok.indexOf('=');
      if (eq > 2) {
        setFlag(tok.slice(2, eq), tok.slice(eq + 1));
      } else {
        const key = tok.slice(2);
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          setFlag(key, next);
          i++;
        } else {
          setFlag(key, true);
        }
      }
    } else if (tok.startsWith('-') && tok.length > 1) {
      const short = tok.slice(1);
      if (short === 'i') setFlag('interactive', true);
      else if (short === 'y') setFlag('yes', true);
      else if (short === 'h') setFlag('help', true);
      else if (short === 'v') setFlag('version', true);
      else if (short === 'e' && argv[i + 1]) {
        setFlag('env', argv[++i]);
      } else if (short === 'H' && argv[i + 1]) {
        setFlag('header', argv[++i]);
      } else {
        setFlag(short, true);
      }
    } else {
      positionals.push(tok);
    }
  }

  return { positionals, flags };
}

export function getStringFlag(
  flags: ParsedCliArgs['flags'],
  key: string,
): string | undefined {
  const v = flags[key];
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v[0];
  return undefined;
}

export function getBoolFlag(flags: ParsedCliArgs['flags'], key: string): boolean {
  const v = flags[key];
  return v === true || v === 'true' || v === '1';
}

export function getListFlag(flags: ParsedCliArgs['flags'], key: string): string[] {
  const v = flags[key];
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') return [v];
  return [];
}

export function parseKeyValuePairs(items: string[], sep = '='): Record<string, string> {
  const out: Record<string, string> = {};
  for (const item of items) {
    const idx = item.indexOf(sep);
    if (idx <= 0) continue;
    out[item.slice(0, idx).trim()] = item.slice(idx + 1).trim();
  }
  return out;
}
