import type { AuditSuite, FlagAdapter, FlagPhase, McpGuardContext, McpGuardPlugin } from '../types.js';

/**
 * Central registry for native and custom FlagAdapters.
 * Allows contributors and plugins to register new CLI flags that read captured MCP
 * context variables and publish their own data back into ContextStore.
 */
export class FlagRegistry {
  private readonly flags = new Map<string, FlagAdapter>();
  private readonly aliases = new Map<string, string>();
  private readonly attachedSuites = new Map<string, AuditSuite>();

  register(adapter: FlagAdapter): void {
    const normalized = adapter.flag.replace(/^--?/, '');
    this.flags.set(normalized, { ...adapter, flag: normalized });
    if (adapter.alias) {
      this.aliases.set(adapter.alias.replace(/^-/, ''), normalized);
    }
    if (adapter.auditSuite) {
      this.attachedSuites.set(adapter.auditSuite.id, adapter.auditSuite);
    }
  }

  registerPlugin(plugin: McpGuardPlugin): void {
    for (const flag of plugin.flags ?? []) {
      this.register(flag);
    }
    for (const suite of plugin.auditSuites ?? []) {
      this.attachedSuites.set(suite.id, suite);
    }
  }

  get(nameOrAlias: string): FlagAdapter | undefined {
    const clean = nameOrAlias.replace(/^--?/, '');
    const resolved = this.aliases.get(clean) ?? clean;
    return this.flags.get(resolved);
  }

  list(): FlagAdapter[] {
    return Array.from(this.flags.values());
  }

  listAttachedSuites(): AuditSuite[] {
    return Array.from(this.attachedSuites.values());
  }

  async runPhase(
    phase: FlagPhase,
    parsedFlags: Record<string, unknown>,
    ctx: McpGuardContext,
  ): Promise<string[]> {
    const executed: string[] = [];
    for (const adapter of this.flags.values()) {
      if (adapter.phase !== phase) continue;
      const val =
        parsedFlags[adapter.flag] ??
        (adapter.alias ? parsedFlags[adapter.alias] : undefined);
      if (val === undefined || val === false) continue;
      await adapter.run(val, ctx);
      executed.push(adapter.flag);
    }
    return executed;
  }
}

export function createFlagRegistry(): FlagRegistry {
  return new FlagRegistry();
}
