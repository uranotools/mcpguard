import type { McpLogEvent, McpProgressEvent, ProgressMode } from '../types.js';
import { ansi } from './ansi.js';

/**
 * Renders live visual progress bars and logs from MCP notifications/progress
 * and notifications/message.
 */
export class ProgressRenderer {
  private lastLineLength = 0;

  constructor(
    private readonly mode: ProgressMode = 'bar',
    private readonly stream: NodeJS.WritableStream = process.stderr,
  ) {}

  onProgress(ev: McpProgressEvent): void {
    if (this.mode === 'quiet') return;
    const total = ev.total && ev.total > 0 ? ev.total : 100;
    const pct = Math.max(0, Math.min(100, Math.round((ev.progress / total) * 100)));
    const msg = ev.message ? ` ${ev.message}` : '';

    if (this.mode === 'steps') {
      this.stream.write(`${ansi.cyan('▸')} [${pct}%]${msg}\n`);
      return;
    }

    const width = 24;
    const filled = Math.round((pct / 100) * width);
    const bar = `${'█'.repeat(filled)}${'░'.repeat(width - filled)}`;
    const line = `${ansi.cyan(bar)} ${ansi.bold(`${pct}%`)}${ansi.dim(msg)}`;
    const pad = Math.max(0, this.lastLineLength - line.length);
    this.lastLineLength = line.length;
    this.stream.write(`\r${line}${' '.repeat(pad)}`);
    if (pct >= 100) this.stream.write('\n');
  }

  onLog(ev: McpLogEvent): void {
    if (this.mode === 'quiet') return;
    const payload = typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data);
    this.stream.write(`\n${ansi.gray(`[${ev.level}]`)} ${payload}\n`);
  }

  done(): void {
    if (this.mode === 'bar' && this.lastLineLength > 0) {
      this.stream.write('\n');
      this.lastLineLength = 0;
    }
  }
}
