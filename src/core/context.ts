import { randomUUID } from 'node:crypto';
import type { McpGuardContext } from '../types.js';

/**
 * Standard native keys automatically populated by the mcpguard pipeline.
 * Any FlagAdapter, SecurityEngine, or AuditSuite can read these keys directly.
 */
export const NATIVE_CONTEXT_KEYS = {
  TARGET: 'mcp.target',
  SERVER_NAME: 'mcp.serverName',
  TRANSPORT: 'mcp.transport',
  SERVER_INFO: 'mcp.serverInfo',
  TOOLS: 'mcp.tools',
  RESOURCES: 'mcp.resources',
  PROMPTS: 'mcp.prompts',
  TOOL_HASHES: 'mcp.toolHashes',
  SECURITY_REPORT: 'mcp.securityReport',
  ARCHITECTURE: 'mcp.architecture',
  CODE_INSPECTION: 'mcp.codeInspection',
  OUTBOUND_URLS: 'mcp.outboundUrls',
  OUTBOUND_DOMAINS: 'mcp.outboundDomains',
  ENV_VARS: 'mcp.envVars',
  INVOCATION_TOOL: 'invocation.toolName',
  INVOCATION_ARGS: 'invocation.args',
  INVOCATION_RESULT: 'invocation.result',
  CLI_FLAGS: 'cli.flags',
} as const;

export class ContextStore implements McpGuardContext {
  readonly runId: string;
  readonly startedAt: string;
  private readonly store = new Map<string, unknown>();
  private readonly provenance = new Map<string, string>();

  constructor(initial?: Record<string, unknown>) {
    this.runId = randomUUID();
    this.startedAt = new Date().toISOString();
    if (initial) {
      for (const [k, v] of Object.entries(initial)) {
        this.store.set(k, v);
        this.provenance.set(k, 'init');
      }
    }
  }

  get<T = unknown>(key: string): T | undefined {
    return this.store.get(key) as T | undefined;
  }

  set<T = unknown>(key: string, value: T): void {
    this.store.set(key, value);
    if (!this.provenance.has(key)) {
      this.provenance.set(key, 'core');
    }
  }

  publish<T = unknown>(key: string, value: T, source = 'plugin'): void {
    this.store.set(key, value);
    this.provenance.set(key, source);
  }

  has(key: string): boolean {
    return this.store.has(key);
  }

  keys(): string[] {
    return Array.from(this.store.keys());
  }

  snapshot(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [k, v] of this.store.entries()) {
      out[k] = v;
    }
    return out;
  }

  sources(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of this.provenance.entries()) {
      out[k] = v;
    }
    return out;
  }
}

export function createContext(initial?: Record<string, unknown>): ContextStore {
  return new ContextStore(initial);
}
