const COLOR_ENABLED = process.env.NO_COLOR === undefined && process.stdout.isTTY !== false;

function wrap(code: string, text: string): string {
  return COLOR_ENABLED ? `\x1b[${code}m${text}\x1b[0m` : text;
}

export function fgRgb(r: number, g: number, b: number, text: string): string {
  return COLOR_ENABLED ? `\x1b[38;2;${r};${g};${b}m${text}\x1b[0m` : text;
}

export function bgRgb(r: number, g: number, b: number, text: string): string {
  return COLOR_ENABLED ? `\x1b[48;2;${r};${g};${b}m${text}\x1b[0m` : text;
}

export function fgHex(hex: string, text: string): string {
  const clean = hex.replace('#', '');
  const r = parseInt(clean.slice(0, 2), 16);
  const g = parseInt(clean.slice(2, 4), 16);
  const b = parseInt(clean.slice(4, 6), 16);
  return fgRgb(r, g, b, text);
}

export const ansi = {
  bold: (s: string) => wrap('1', s),
  dim: (s: string) => wrap('2', s),
  inverse: (s: string) => wrap('7', s),
  red: (s: string) => wrap('31', s),
  green: (s: string) => wrap('32', s),
  yellow: (s: string) => wrap('33', s),
  blue: (s: string) => wrap('34', s),
  magenta: (s: string) => wrap('35', s),
  cyan: (s: string) => wrap('36', s),
  gray: (s: string) => wrap('90', s),
  // Editorial Terminal High-Contrast Palette
  ink: (s: string) => fgHex('#E8E6DF', s),
  muted: (s: string) => fgHex('#7A7870', s),
  grid: (s: string) => fgHex('#4A4944', s),
  amber: (s: string) => fgHex('#FF5500', s),
  phosphor: (s: string) => fgHex('#00FF66', s),
};
