import { ansi } from './ansi.js';

export type BannerStyle = 'block' | 'compact' | 'ascii';
export type BannerAccent = 'amber' | 'phosphor';

/**
 * Official UranoTools Open Source planet logo — EXACT 24x12 square geometry
 * (24x24 half-block sub-pixels, zero horizontal stretch) with orbital moons.
 * Reusable across any @uranotools/* CLI project.
 */
export const URANO_LOGO_BLOCK: readonly string[] = [
  '·                      ✦',
  '         ▄▄▄▄▄▄     ▄▄  ',
  '      ▄██████████▄ ▄▀▀  ',
  '    ▄████▀▀▀▀▀▀████▄▄   ',
  '   ▄███▀▄█▀▀▀▀█▄▀███▄ ▀▄',
  '   ███▀▄█▄████▄█▄▀███  █',
  ' ▄▀▄▄▄ ▄▄▀████▀▄▄ ▄▄▄▀▀ ',
  '█  ▀███ ▀▄█▀▀█▄▀ ████   ',
  '▀ ▄▄████▄▄▀▀▀▀▄▄███▀  ◐ ',
  '     ▀▀██████████▀▀     ',
  '        ▀▀▀▀▀▀▀▀        ',
  '☾                      ·',
];

/**
 * Compact exact-square 22x12 variant for narrow terminals.
 */
export const URANO_LOGO_COMPACT: readonly string[] = [
  '·                    ✦',
  '        ▄▄▄▄▄▄    ▄▄  ',
  '     ▄██████████▄ ▀▀  ',
  '    ████▀▀▀▀▀▀█▀▄█▄   ',
  '   ███▀▄█▀▀▀▀▀▄▀███ ▀█',
  '   ███ █ ████ █ ███  █',
  ' ▄▀▄▄▄ ▄▀████ ▄ ▄▄▄▀▀ ',
  '█  ███▄▀██▀▀▄█▀▄███   ',
  '▀▄▄▄███▄▄▀▀▀▀▄▄███  ◐ ',
  '     ▀██████████▀     ',
  '        ▀▀▀▀▀▀        ',
  '☾                    ·',
];

/**
 * Pure 7-bit ASCII exact-square 24x12 variant for legacy/dumb terminals.
 */
export const URANO_LOGO_ASCII: readonly string[] = [
  '.                      *',
  '         .====.     (o) ',
  '      .##########. /    ',
  '    .####*----*####=.   ',
  '   .###* .#--#. *###. +.',
  '   ###* .#.###.#.*###  |',
  ' .+===  ==*##*==  ===++ ',
  '|  *###  *#--#*  ####   ',
  '+ ==####==----==###*  o ',
  '     **##########**     ',
  '        ********        ',
  '(                      .',
];

/**
 * Calligraphic ("Scrittura Bella" / Lucida Calligraphy) half-block
 * wordmark for "Urano Tools" (12 lines, 46 cols).
 */
export const URANO_WORDMARK_CALLIGRAPHY: readonly string[] = [
  ' ▄ ▀██    █▀                                  ',
  '█▀ ▄█    ██  ▄ █ ▄▄█   ▄ ▀██ ▄ █▄ ▄██    ▄ ▀█▄',
  '   ██    █▀ ▀ ▄██▀   ▄▀  ▄█    ██▀ ██  ▄█   ██',
  '   ██   ▄█    ██    ▄█  ▄██   ▄█   █▀ ▄██   █▀',
  '   ▀▀  ▀▀▀ ▀  ▀     ▀▀▀▀ ▀▀ ▀ ▀▀   ▀ ▀ ▀▀  ▀  ',
  '                                              ',
  '                  ▄                  ▄▄▄      ',
  '         ▄▄▄▄▄▄▄ ▀                ▄▀          ',
  '       █   ▄█      ▄▄▄     ▄▄▄   ▄█    ▄▄▄    ',
  '      ▀▀   ██    █▀  ██  █▀  ██  █▀  ██  ▀    ',
  '          ▄█    ██   █▀ ██   █▀ ██    ▀█▄     ',
  '        ▄▄█▄    ▀█▄▄▀   ▀█▄▄▀   ██▄▀▄▄▄▄▀     ',
];

/**
 * Pure 7-bit ASCII calligraphic fallback for "Urano Tools" (12 lines, 46 cols).
 */
export const URANO_WORDMARK_ASCII: readonly string[] = [
  '  .  *##   #*                                 ',
  ' #* .#    ##  . # ..#   . *## . #. .##   . *#.',
  '    ##    #* * .##*   .*  .#    ##* ##  .#  ##',
  '    ##   .#    ##    .#  .##   .#   #* .##  #*',
  '    **  *** *  *     **** ** * **   * * **  * ',
  '                                              ',
  '                   .                 ...      ',
  '         ....... *                .*          ',
  '       #   .#      ...     ...   .#    ...    ',
  '      **   ##    #*  ##  #*  ##  #*  ##  *    ',
  '          .#    ##   #* ##   #* ##    *#.     ',
  '        ..#.    *#..*   *#..*   ##.*....*     ',
];

export const URANO_WORDMARK_BLOCK = URANO_WORDMARK_CALLIGRAPHY;

export interface UranoBannerOptions {
  /** Product / CLI name, e.g. "mcpguard", "urano-guard", "urano-social". */
  product: string;
  /** Package version string, e.g. "0.1.0". */
  version?: string;
  /** Short one-line tagline shown below the banner. */
  tagline?: string;
  /** Organization / signature shown below the wordmark. */
  org?: string;
  /** Optional URL or repository shown below the banner. */
  url?: string;
  /** Logo rendering style: 'block' (default), 'compact', or 'ascii'. */
  style?: BannerStyle;
  /** Accent color: 'amber' (#FF5500, default) or 'phosphor' (#00FF66). */
  accent?: BannerAccent;
  /** Disable ANSI color codes. */
  plain?: boolean;
}

export function getUranoLogo(style: BannerStyle = 'block'): readonly string[] {
  switch (style) {
    case 'compact':
      return URANO_LOGO_COMPACT;
    case 'ascii':
      return URANO_LOGO_ASCII;
    case 'block':
    default:
      return URANO_LOGO_BLOCK;
  }
}

/**
 * Renders a clean, borderless reusable UranoTools CLI banner pairing the exact-square
 * planet logo with calligraphic "Urano Tools" lettering directly on the terminal surface.
 */
export function renderUranoBanner(opts: UranoBannerOptions): string {
  const style = opts.style ?? 'block';
  const isAscii = style === 'ascii';
  const logo = getUranoLogo(style);
  const wordmark = isAscii ? URANO_WORDMARK_ASCII : URANO_WORDMARK_CALLIGRAPHY;
  const ver = opts.version ?? '0.1.0';
  const org = opts.org ?? 'UranoTools Open Source';

  const accentFn = opts.accent === 'phosphor' ? ansi.phosphor : ansi.amber;
  const c = opts.plain
    ? {
        ink: (s: string) => s,
        muted: (s: string) => s,
        accent: (s: string) => s,
        bold: (s: string) => s,
      }
    : {
        ink: ansi.ink,
        muted: ansi.muted,
        accent: accentFn,
        bold: ansi.bold,
      };

  const logoW = Math.max(...logo.map((l) => l.length));
  const lines: string[] = [];

  for (let i = 0; i < 12; i++) {
    const leftRaw = (logo[i] ?? '').padEnd(logoW, ' ');
    const rightRaw = wordmark[i] ?? '';
    const left = c.ink(leftRaw);
    const right = i < 6 ? c.bold(c.ink(rightRaw)) : c.bold(c.accent(rightRaw));
    lines.push(`  ${left}    ${right}`);
  }

  lines.push('');
  const meta = `${c.accent(isAscii ? '>' : '▸')} ${c.bold(c.ink(`${opts.product} v${ver}`))}${opts.tagline ? `  ${c.muted(`·  ${opts.tagline}`)}` : ''}`;
  lines.push(`  ${meta}`);
  lines.push(`    ${c.muted(`${org}${opts.url ? `  ·  ${opts.url}` : ''}`)}`);

  return lines.join('\n');
}

/**
 * Optional stepped-linear stagger reveal (35ms/line) for CLI startup.
 */
export async function playUranoBannerAnimated(
  opts: UranoBannerOptions,
  staggerMs = 35,
  stream: NodeJS.WritableStream = process.stdout,
): Promise<void> {
  const rendered = renderUranoBanner(opts).split('\n');
  for (const line of rendered) {
    stream.write(`${line}\n`);
    if (staggerMs > 0) {
      await new Promise((r) => setTimeout(r, staggerMs));
    }
  }
}
