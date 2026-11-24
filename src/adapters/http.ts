import type { McpTransportAdapter, RequestOptions } from '../types.js';

export interface HttpAdapterOptions {
  url: string;
  headers?: Record<string, string>;
  bearerToken?: string;
  apiKey?: string;
  apiKeyHeader?: string;
}

export class HttpAuthRequiredError extends Error {
  readonly status = 401;
  constructor(
    message: string,
    readonly wwwAuthenticate?: string,
  ) {
    super(message);
    this.name = 'HttpAuthRequiredError';
  }
}

/**
 * Streamable HTTP + SSE MCP transport adapter.
 * Supports JSON responses and Server-Sent Events streams carrying JSON-RPC
 * notifications (notifications/progress, notifications/message) before the final result.
 */
export class HttpTransportAdapter implements McpTransportAdapter {
  readonly kind = 'http' as const;
  readonly target: string;

  private nextId = 1;
  private sessionId: string | undefined;
  private readonly listeners = new Set<(method: string, params: Record<string, unknown>) => void>();

  constructor(private readonly opts: HttpAdapterOptions) {
    this.target = opts.url;
  }

  async connect(): Promise<void> {
    // Streamable HTTP connects lazily on initialize
  }

  async disconnect(): Promise<void> {
    this.sessionId = undefined;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...this.opts.headers,
    };
    if (this.opts.bearerToken) {
      headers.authorization = `Bearer ${this.opts.bearerToken}`;
    } else if (this.opts.apiKey) {
      headers[this.opts.apiKeyHeader ?? 'x-api-key'] = this.opts.apiKey;
    }
    if (this.sessionId) {
      headers['mcp-session-id'] = this.sessionId;
    }
    return headers;
  }

  async request<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    opts: RequestOptions = {},
  ): Promise<T> {
    const id = this.nextId++;
    const controller = new AbortController();
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(this.opts.url, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: opts.signal ?? controller.signal,
      });

      const sid = res.headers.get('mcp-session-id');
      if (sid) this.sessionId = sid;

      if (res.status === 401) {
        throw new HttpAuthRequiredError(
          `Authentication required by ${this.opts.url}`,
          res.headers.get('www-authenticate') ?? undefined,
        );
      }

      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`HTTP ${res.status} from ${this.opts.url}: ${text.slice(0, 300)}`);
      }

      const contentType = res.headers.get('content-type') ?? '';
      if (contentType.includes('text/event-stream')) {
        return (await this.consumeSseResponse(res, id)) as T;
      }

      const body = (await res.json()) as {
        result?: T;
        error?: { code?: number; message?: string };
      };
      if (body.error) {
        throw new Error(`MCP error ${body.error.code ?? ''}: ${body.error.message ?? 'Unknown error'}`);
      }
      return body.result as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async notify(method: string, params: Record<string, unknown> = {}): Promise<void> {
    try {
      await fetch(this.opts.url, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: JSON.stringify({ jsonrpc: '2.0', method, params }),
      });
    } catch {
      // Best-effort notification
    }
  }

  private async consumeSseResponse(res: Response, expectedId: number): Promise<unknown> {
    const reader = res.body?.getReader();
    if (!reader) throw new Error('Empty SSE stream from MCP server');

    const decoder = new TextDecoder();
    let buffer = '';
    let finalResult: unknown = undefined;
    let hasResult = false;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const frames = buffer.split(/\r?\n\r?\n/);
      buffer = frames.pop() ?? '';

      for (const frame of frames) {
        const dataLines = frame
          .split(/\r?\n/)
          .filter((l) => l.startsWith('data:'))
          .map((l) => l.slice(5).trim());
        if (dataLines.length === 0) continue;

        const raw = dataLines.join('\n');
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(raw) as Record<string, unknown>;
        } catch {
          continue;
        }

        if (typeof msg.method === 'string') {
          const params = (msg.params && typeof msg.params === 'object' ? msg.params : {}) as Record<
            string,
            unknown
          >;
          for (const listener of this.listeners) {
            listener(msg.method, params);
          }
        } else if (msg.id === expectedId) {
          if (msg.error && typeof msg.error === 'object') {
            const errObj = msg.error as { code?: number; message?: string };
            throw new Error(`MCP error ${errObj.code ?? ''}: ${errObj.message ?? 'Unknown error'}`);
          }
          finalResult = msg.result;
          hasResult = true;
        }
      }
    }

    if (!hasResult) {
      throw new Error('SSE stream ended without a matching JSON-RPC response');
    }
    return finalResult;
  }

  onNotification(handler: (method: string, params: Record<string, unknown>) => void): () => void {
    this.listeners.add(handler);
    return () => {
      this.listeners.delete(handler);
    };
  }
}
