import { createHmac, randomUUID } from 'node:crypto';
import type {
  McpToolCallResult,
  McpToolDefinition,
  McpTransportAdapter,
  RequestOptions,
} from '../types.js';

export interface UranoWebhookAdapterOptions {
  url: string;
  secret: string;
  headers?: Record<string, string>;
}

const URANO_WEBHOOK_TOOLS: McpToolDefinition[] = [
  {
    name: 'chat',
    description: 'Send a message to a Urano agent webhook signed with HMAC (x-urano-signature).',
    annotations: { openWorldHint: true },
    inputSchema: {
      type: 'object',
      required: ['text'],
      properties: {
        text: {
          type: 'string',
          title: 'Message',
          description: 'Message text sent to the Urano agent',
          'x-section': 'Message',
        },
        displayName: {
          type: 'string',
          title: 'Display Name',
          description: 'Optional caller display name',
          'x-section': 'Identity',
        },
        sessionId: {
          type: 'string',
          title: 'Session ID',
          description: 'Optional existing session identifier',
          'x-section': 'Identity',
        },
      },
    },
  },
  {
    name: 'contact',
    description: 'Submit an async contact payload to a Urano SalesAgentConnector webhook.',
    annotations: { openWorldHint: true },
    inputSchema: {
      type: 'object',
      required: ['name', 'email', 'message'],
      properties: {
        name: { type: 'string', title: 'Name', 'x-section': 'Contact' },
        email: { type: 'string', title: 'Email', 'x-section': 'Contact' },
        message: { type: 'string', title: 'Message', 'x-section': 'Details' },
      },
    },
  },
];

/**
 * Optional adapter for Urano HMAC-signed webhooks (compatible with @uranotools/urano-social).
 */
export class UranoWebhookAdapter implements McpTransportAdapter {
  readonly kind = 'urano-webhook' as const;
  readonly target: string;
  private readonly listeners = new Set<(method: string, params: Record<string, unknown>) => void>();

  constructor(private readonly opts: UranoWebhookAdapterOptions) {
    this.target = opts.url;
  }

  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}

  onNotification(handler: (method: string, params: Record<string, unknown>) => void): () => void {
    this.listeners.add(handler);
    return () => {
      this.listeners.delete(handler);
    };
  }

  async request<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    opts: RequestOptions = {},
  ): Promise<T> {
    if (method === 'initialize') {
      return {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'urano-webhook', version: '1.0.0' },
        capabilities: { tools: {} },
      } as T;
    }
    if (method === 'tools/list') {
      return { tools: URANO_WEBHOOK_TOOLS } as T;
    }
    if (method === 'resources/list') return { resources: [] } as T;
    if (method === 'prompts/list') return { prompts: [] } as T;

    if (method === 'tools/call') {
      const toolName = String(params.name ?? 'chat');
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      const bodyStr = JSON.stringify({
        type: toolName,
        mode: 'wait',
        ...args,
      });
      const signature = createHmac('sha256', this.opts.secret).update(bodyStr).digest('hex');

      const res = await fetch(this.opts.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-urano-signature': signature,
          'idempotency-key': randomUUID(),
          ...this.opts.headers,
        },
        body: bodyStr,
        signal: opts.signal,
      });

      const text = await res.text();
      const result: McpToolCallResult = {
        isError: !res.ok,
        content: [{ type: 'text', text }],
      };
      return result as T;
    }

    throw new Error(`Unsupported method "${method}" on urano-webhook adapter`);
  }
}
