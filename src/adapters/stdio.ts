import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { McpTransportAdapter, RequestOptions } from '../types.js';

export interface StdioAdapterOptions {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  egressProxyUrl?: string;
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timer?: NodeJS.Timeout;
}

export class StdioTransportAdapter implements McpTransportAdapter {
  readonly kind = 'stdio' as const;
  readonly target: string;

  private proc: ChildProcessWithoutNullStreams | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, PendingRequest>();
  private readonly listeners = new Set<(method: string, params: Record<string, unknown>) => void>();
  private readonly stderrChunks: string[] = [];

  constructor(private readonly opts: StdioAdapterOptions) {
    this.target = [opts.command, ...(opts.args ?? [])].join(' ');
  }

  async connect(): Promise<void> {
    if (this.proc) return;
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...this.opts.env,
    };
    if (this.opts.egressProxyUrl) {
      env.HTTP_PROXY = this.opts.egressProxyUrl;
      env.HTTPS_PROXY = this.opts.egressProxyUrl;
      env.http_proxy = this.opts.egressProxyUrl;
      env.https_proxy = this.opts.egressProxyUrl;
    }

    const child = spawn(this.opts.command, this.opts.args ?? [], {
      cwd: this.opts.cwd,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: process.platform === 'win32' && /\.(cmd|bat)$/i.test(this.opts.command),
    });

    this.proc = child;

    const rl = createInterface({ input: child.stdout });
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      this.handleLine(trimmed);
    });

    child.stderr.on('data', (chunk: Buffer) => {
      this.stderrChunks.push(chunk.toString('utf8'));
      if (this.stderrChunks.length > 50) this.stderrChunks.shift();
    });

    child.on('exit', (code) => {
      const errMsg = `MCP stdio process exited (code ${code ?? 'null'}). ${this.stderrChunks.slice(-3).join('').trim()}`;
      for (const [, p] of this.pending.entries()) {
        if (p.timer) clearTimeout(p.timer);
        p.reject(new Error(errMsg));
      }
      this.pending.clear();
      this.proc = null;
    });

    child.on('error', (err) => {
      for (const [, p] of this.pending.entries()) {
        if (p.timer) clearTimeout(p.timer);
        p.reject(err);
      }
      this.pending.clear();
      this.proc = null;
    });
  }

  private handleLine(line: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return; // Ignore non-JSON stdout noise
    }

    if (typeof msg.id === 'number' && this.pending.has(msg.id)) {
      const entry = this.pending.get(msg.id)!;
      this.pending.delete(msg.id);
      if (entry.timer) clearTimeout(entry.timer);
      if (msg.error && typeof msg.error === 'object') {
        const errObj = msg.error as { code?: number; message?: string };
        entry.reject(new Error(`MCP error ${errObj.code ?? ''}: ${errObj.message ?? 'Unknown error'}`));
      } else {
        entry.resolve(msg.result);
      }
      return;
    }

    if (typeof msg.method === 'string') {
      const params = (msg.params && typeof msg.params === 'object' ? msg.params : {}) as Record<
        string,
        unknown
      >;
      for (const listener of this.listeners) {
        listener(msg.method, params);
      }
    }
  }

  async request<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    opts: RequestOptions = {},
  ): Promise<T> {
    if (!this.proc) await this.connect();
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });

    return new Promise<T>((resolve, reject) => {
      const timeoutMs = opts.timeoutMs ?? 30_000;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`MCP stdio request "${method}" timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
      });

      this.proc!.stdin.write(`${payload}\n`, (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  async notify(method: string, params: Record<string, unknown> = {}): Promise<void> {
    if (!this.proc) return;
    const payload = JSON.stringify({ jsonrpc: '2.0', method, params });
    this.proc.stdin.write(`${payload}\n`);
  }

  onNotification(handler: (method: string, params: Record<string, unknown>) => void): () => void {
    this.listeners.add(handler);
    return () => {
      this.listeners.delete(handler);
    };
  }

  async disconnect(): Promise<void> {
    if (!this.proc) return;
    const child = this.proc;
    this.proc = null;
    try {
      child.stdin.end();
      child.kill();
    } catch {
      // Ignore already exited
    }
  }
}
