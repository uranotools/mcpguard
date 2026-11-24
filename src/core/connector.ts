import { randomUUID } from 'node:crypto';
import type {
  McpGuardContext,
  McpLogEvent,
  McpProgressEvent,
  McpPromptDefinition,
  McpResourceDefinition,
  McpServerInfo,
  McpToolCallResult,
  McpToolDefinition,
  McpTransportAdapter,
  NormalizedToolForm,
} from '../types.js';
import { NATIVE_CONTEXT_KEYS } from './context.js';
import { buildToolForm } from './schemaForm.js';

export interface McpDiscoveryResult {
  serverInfo: McpServerInfo;
  tools: McpToolDefinition[];
  resources: McpResourceDefinition[];
  prompts: McpPromptDefinition[];
}

export interface ConnectorCallOptions {
  timeoutMs?: number;
  onProgress?: (ev: McpProgressEvent) => void;
  onLog?: (ev: McpLogEvent) => void;
  clientInfo?: { name: string; version: string };
}

/**
 * Normalized MCP Connector.
 * Wraps any McpTransportAdapter, performs single-pass discovery, populates ContextStore,
 * and streams notifications/progress & notifications/message during tool calls.
 */
export class McpConnector {
  private connected = false;
  private initialized = false;
  private serverInfo: McpServerInfo = { name: 'unknown' };
  private cachedTools: McpToolDefinition[] | null = null;

  constructor(
    readonly adapter: McpTransportAdapter,
    private readonly context?: McpGuardContext,
  ) {}

  async connect(clientInfo = { name: 'mcpguard', version: '0.1.0' }): Promise<McpServerInfo> {
    if (!this.connected) {
      await this.adapter.connect();
      this.connected = true;
    }
    if (!this.initialized) {
      const res = await this.adapter.request<{
        protocolVersion?: string;
        serverInfo?: { name: string; version?: string };
        capabilities?: Record<string, unknown>;
      }>('initialize', {
        protocolVersion: '2025-03-26',
        capabilities: {},
        clientInfo,
      });

      this.serverInfo = {
        name: res?.serverInfo?.name ?? 'mcp-server',
        version: res?.serverInfo?.version,
        protocolVersion: res?.protocolVersion,
        capabilities: res?.capabilities,
      };
      if (this.adapter.notify) {
        await this.adapter.notify('notifications/initialized', {});
      }
      this.initialized = true;
      this.context?.set(NATIVE_CONTEXT_KEYS.SERVER_INFO, this.serverInfo);
      this.context?.set(NATIVE_CONTEXT_KEYS.TRANSPORT, this.adapter.kind);
      this.context?.set(NATIVE_CONTEXT_KEYS.TARGET, this.adapter.target);
    }
    return this.serverInfo;
  }

  async discover(clientInfo?: { name: string; version: string }): Promise<McpDiscoveryResult> {
    const serverInfo = await this.connect(clientInfo);

    const toolsRes = await this.adapter.request<{ tools?: McpToolDefinition[] }>('tools/list', {});
    const tools = toolsRes?.tools ?? [];
    this.cachedTools = tools;

    let resources: McpResourceDefinition[] = [];
    try {
      const resList = await this.adapter.request<{ resources?: McpResourceDefinition[] }>('resources/list', {});
      resources = resList?.resources ?? [];
    } catch {
      // Optional capability
    }

    let prompts: McpPromptDefinition[] = [];
    try {
      const promptList = await this.adapter.request<{ prompts?: McpPromptDefinition[] }>('prompts/list', {});
      prompts = promptList?.prompts ?? [];
    } catch {
      // Optional capability
    }

    this.context?.set(NATIVE_CONTEXT_KEYS.TOOLS, tools);
    this.context?.set(NATIVE_CONTEXT_KEYS.RESOURCES, resources);
    this.context?.set(NATIVE_CONTEXT_KEYS.PROMPTS, prompts);

    return { serverInfo, tools, resources, prompts };
  }

  async getToolForm(toolName: string): Promise<{ tool: McpToolDefinition; form: NormalizedToolForm }> {
    const tools = this.cachedTools ?? (await this.discover()).tools;
    const tool = tools.find((t) => t.name === toolName);
    if (!tool) {
      throw new Error(
        `Tool "${toolName}" not found. Available: ${tools.map((t) => t.name).join(', ') || '(none)'}`,
      );
    }
    return { tool, form: buildToolForm(tool) };
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
    opts: ConnectorCallOptions = {},
  ): Promise<McpToolCallResult> {
    await this.connect(opts.clientInfo);
    const progressToken = `mcpg-${randomUUID().slice(0, 8)}`;

    const unsubscribe = this.adapter.onNotification((method, params) => {
      if (method === 'notifications/progress' && opts.onProgress) {
        const token = params.progressToken as string | number | undefined;
        if (token === undefined || token === progressToken) {
          opts.onProgress({
            progressToken: token ?? progressToken,
            progress: Number(params.progress ?? 0),
            total: params.total !== undefined ? Number(params.total) : undefined,
            message: typeof params.message === 'string' ? params.message : undefined,
          });
        }
      } else if (method === 'notifications/message' && opts.onLog) {
        opts.onLog({
          level: String(params.level ?? 'info'),
          logger: typeof params.logger === 'string' ? params.logger : undefined,
          data: params.data,
        });
      }
    });

    this.context?.set(NATIVE_CONTEXT_KEYS.INVOCATION_TOOL, name);
    this.context?.set(NATIVE_CONTEXT_KEYS.INVOCATION_ARGS, args);

    try {
      const result = await this.adapter.request<McpToolCallResult>(
        'tools/call',
        {
          name,
          arguments: args,
          _meta: { progressToken },
        },
        {
          timeoutMs: opts.timeoutMs,
          progressToken,
        },
      );
      this.context?.set(NATIVE_CONTEXT_KEYS.INVOCATION_RESULT, result);
      return result;
    } finally {
      unsubscribe();
    }
  }

  async disconnect(): Promise<void> {
    if (this.connected) {
      await this.adapter.disconnect();
      this.connected = false;
      this.initialized = false;
    }
  }
}
