import type { McpServerConfig, McpTransportAdapter } from '../types.js';
import { HttpTransportAdapter } from './http.js';
import { StdioTransportAdapter } from './stdio.js';
import { UranoWebhookAdapter } from './uranoWebhook.js';

export { StdioTransportAdapter } from './stdio.js';
export type { StdioAdapterOptions } from './stdio.js';
export { HttpTransportAdapter, HttpAuthRequiredError } from './http.js';
export type { HttpAdapterOptions } from './http.js';
export { UranoWebhookAdapter } from './uranoWebhook.js';
export type { UranoWebhookAdapterOptions } from './uranoWebhook.js';

export interface CreateAdapterOptions {
  secret?: string;
  egressProxyUrl?: string;
}

export function createTransportAdapter(
  cfg: McpServerConfig,
  opts: CreateAdapterOptions = {},
): McpTransportAdapter {
  switch (cfg.adapter) {
    case 'stdio':
      return new StdioTransportAdapter({
        command: cfg.target,
        args: cfg.args,
        env: cfg.env,
        egressProxyUrl: opts.egressProxyUrl,
      });
    case 'http':
    case 'sse':
      return new HttpTransportAdapter({
        url: cfg.target,
        headers: cfg.headers,
        bearerToken:
          cfg.auth === 'bearer' || cfg.auth === 'oauth' || (cfg.auth === 'auto' && Boolean(opts.secret))
            ? opts.secret
            : undefined,
        apiKey: cfg.auth === 'api-key' ? opts.secret : undefined,
      });
    case 'urano-webhook':
      return new UranoWebhookAdapter({
        url: cfg.target,
        secret: opts.secret ?? '',
        headers: cfg.headers,
      });
    default:
      throw new Error(`Unsupported transport adapter: ${String(cfg.adapter)}`);
  }
}

export function splitCommandLine(raw: string): { command: string; args: string[] } {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) tokens.push(current);
  const [command = '', ...args] = tokens;
  return { command, args };
}
