import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import type {
  AuthMode,
  McpGuardPlugin,
  McpServerConfig,
  SecurityEngine,
  SecurityReport,
  TransportKind,
} from '../types.js';
import { createTransportAdapter, splitCommandLine } from '../adapters/index.js';
import { AuditRunner } from '../core/auditRunner.js';
import { McpConnector, type McpDiscoveryResult } from '../core/connector.js';
import { ContextStore, createContext, NATIVE_CONTEXT_KEYS } from '../core/context.js';
import { FlagRegistry, createFlagRegistry } from '../core/flagRegistry.js';
import { ConfigRegistry } from '../core/registry.js';
import { resolveAiProvider } from '../providers/index.js';
import { runSecurityScan, TrustLockStore } from '../security/index.js';
import { getBoolFlag, getListFlag, getStringFlag, parseKeyValuePairs, type ParsedCliArgs } from './args.js';

export interface ResolvedTarget {
  config: McpServerConfig;
  secret?: string;
  localPath?: string;
  isRegistered: boolean;
}

/**
 * Single closed-loop pipeline shared across install, scan, audit, report, and invoke.
 * Connects ONCE, populates ContextStore, feeds security engines, custom FlagAdapters,
 * and AuditSuites from the exact same captured MCP data.
 */
export class McpGuardPipeline {
  readonly registry: ConfigRegistry;
  readonly trustLock: TrustLockStore;
  readonly flagRegistry: FlagRegistry;
  readonly auditRunner: AuditRunner;
  readonly extraEngines: SecurityEngine[] = [];

  constructor(baseDir?: string) {
    this.registry = new ConfigRegistry(baseDir);
    this.trustLock = new TrustLockStore(baseDir);
    this.flagRegistry = createFlagRegistry();
    this.auditRunner = new AuditRunner(true);
  }

  async loadPlugins(paths: string[]): Promise<void> {
    for (const p of paths) {
      const modUrl = p.startsWith('file://') ? p : pathToFileURL(p).href;
      const mod = (await import(modUrl)) as { default?: McpGuardPlugin; plugin?: McpGuardPlugin };
      const plugin = mod.default ?? mod.plugin;
      if (!plugin) continue;
      this.flagRegistry.registerPlugin(plugin);
      for (const suite of plugin.auditSuites ?? []) this.auditRunner.register(suite);
      for (const flag of plugin.flags ?? []) {
        if (flag.auditSuite) this.auditRunner.register(flag.auditSuite);
      }
      if (plugin.securityEngines) this.extraEngines.push(...plugin.securityEngines);
    }
  }

  resolveTarget(targetOrName: string, flags: ParsedCliArgs['flags']): ResolvedTarget {
    const saved = this.registry.getServer(targetOrName);
    if (saved) {
      const secret = saved.secretRef ? this.registry.vault.get(saved.secretRef) : undefined;
      return {
        config: saved,
        secret,
        localPath: inferLocalPathFromConfig(saved),
        isRegistered: true,
      };
    }

    const adapterFlag = getStringFlag(flags, 'adapter') as TransportKind | 'auto' | undefined;
    const authFlag = (getStringFlag(flags, 'auth') as AuthMode | undefined) ?? 'auto';
    const headers = parseKeyValuePairs(getListFlag(flags, 'header'), ':');
    const env = parseKeyValuePairs(getListFlag(flags, 'env'), '=');

    const isUrl = targetOrName.startsWith('http://') || targetOrName.startsWith('https://');
    const adapter: TransportKind =
      adapterFlag && adapterFlag !== 'auto'
        ? adapterFlag
        : isUrl
          ? 'http'
          : 'stdio';

    let target = targetOrName;
    let args: string[] = [];
    if (adapter === 'stdio') {
      const parsed = splitCommandLine(targetOrName);
      target = parsed.command;
      args = parsed.args;
    }

    const secret =
      getStringFlag(flags, 'token') ??
      getStringFlag(flags, 'api-key') ??
      (getStringFlag(flags, 'secret-env') ? process.env[getStringFlag(flags, 'secret-env')!] : undefined);

    const config: McpServerConfig = {
      name: getStringFlag(flags, 'name') ?? deriveServerName(targetOrName),
      adapter,
      target,
      args: args.length > 0 ? args : undefined,
      env: Object.keys(env).length > 0 ? env : undefined,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      auth: authFlag,
      installedAt: new Date().toISOString(),
    };

    const localPath = existsSync(targetOrName) ? targetOrName : inferLocalPathFromConfig(config);
    return { config, secret, localPath, isRegistered: false };
  }

  async connectAndScan(
    targetOrName: string,
    parsed: ParsedCliArgs,
    opts: {
      skipDiscoveryIfLocalOnly?: boolean;
      onEngineStart?: (index: number, total: number, name: string) => void;
      onEngineDone?: (index: number, total: number, res: import('../types.js').SecurityEngineResult) => void;
    } = {},
  ): Promise<{
    ctx: ContextStore;
    resolved: ResolvedTarget;
    connector?: McpConnector;
    discovery?: McpDiscoveryResult;
    report: SecurityReport;
  }> {
    const ctx = createContext({ [NATIVE_CONTEXT_KEYS.CLI_FLAGS]: parsed.flags });
    await this.loadPlugins(getListFlag(parsed.flags, 'plugin'));
    await this.flagRegistry.runPhase('pre-connect', parsed.flags, ctx);

    const resolved = this.resolveTarget(targetOrName, parsed.flags);
    ctx.set(NATIVE_CONTEXT_KEYS.TARGET, resolved.config.target);
    ctx.set(NATIVE_CONTEXT_KEYS.SERVER_NAME, resolved.config.name);
    ctx.set(NATIVE_CONTEXT_KEYS.TRANSPORT, resolved.config.adapter);

    let connector: McpConnector | undefined;
    let discovery: McpDiscoveryResult | undefined;

    // Allow static-only scanning of a local directory/file path without executing it
    const isPlainLocalDir =
      opts.skipDiscoveryIfLocalOnly &&
      resolved.config.adapter === 'stdio' &&
      existsSync(targetOrName) &&
      (!resolved.config.args || resolved.config.args.length === 0);

    if (!isPlainLocalDir) {
      const adapter = createTransportAdapter(resolved.config, { secret: resolved.secret });
      connector = new McpConnector(adapter, ctx);
      discovery = await connector.discover();
      await this.flagRegistry.runPhase('post-discover', parsed.flags, ctx);
    } else {
      ctx.set(NATIVE_CONTEXT_KEYS.TOOLS, []);
      ctx.set(NATIVE_CONTEXT_KEYS.RESOURCES, []);
      ctx.set(NATIVE_CONTEXT_KEYS.PROMPTS, []);
    }

    const aiProvider = resolveAiProvider(
      this.registry,
      getStringFlag(parsed.flags, 'ai-provider'),
      getStringFlag(parsed.flags, 'ai-model'),
    );

    const cfg = this.registry.load();
    const report = await runSecurityScan(
      {
        target: resolved.config.target,
        serverName: resolved.isRegistered ? resolved.config.name : undefined,
        transport: resolved.config.adapter,
        serverInfo: discovery?.serverInfo,
        tools: discovery?.tools ?? [],
        resources: discovery?.resources ?? [],
        prompts: discovery?.prompts ?? [],
        localPath: resolved.localPath,
        command: resolved.config.adapter === 'stdio' ? resolved.config.target : undefined,
        args: resolved.config.args,
        headers: resolved.config.headers,
        oauthScopes: resolved.config.oauth?.scopes,
        deep: getBoolFlag(parsed.flags, 'deep'),
        probe: getBoolFlag(parsed.flags, 'probe'),
        expandMeta: getBoolFlag(parsed.flags, 'expand-meta'),
        checkCloaking: !getBoolFlag(parsed.flags, 'no-cloaking'),
        vtApiKey: getStringFlag(parsed.flags, 'vt-key'),
        threatFeeds: [...(cfg.threatFeeds ?? []), ...getListFlag(parsed.flags, 'threat-feed')],
        aiProvider,
        connector,
        contextStore: ctx,
      },
      {
        extraEngines: this.extraEngines,
        trustLockStore: this.trustLock,
        skipNetworkEngines: getBoolFlag(parsed.flags, 'offline'),
        onlyEngines: getListFlag(parsed.flags, 'only'),
        onEngineStart: opts.onEngineStart,
        onEngineDone: opts.onEngineDone,
      },
    );

    await this.flagRegistry.runPhase('post-scan', parsed.flags, ctx);
    return { ctx, resolved, connector, discovery, report };
  }
}

export function deriveServerName(target: string): string {
  try {
    if (target.startsWith('http://') || target.startsWith('https://')) {
      const host = new URL(target).hostname.replace(/^www\./, '');
      return host.split('.')[0].replace(/[^a-zA-Z0-9_-]/g, '-').toLowerCase() || 'remote-mcp';
    }
  } catch {
    // fallback
  }
  const clean = target
    .split(/\s+/)
    .filter((t) => !t.startsWith('-'))
    .pop() ?? 'local-mcp';
  return clean
    .replace(/^@[^/]+\//, '')
    .replace(/[^a-zA-Z0-9_-]/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase() || 'local-mcp';
}

function inferLocalPathFromConfig(cfg: McpServerConfig): string | undefined {
  if (cfg.adapter !== 'stdio') return undefined;
  if (existsSync(cfg.target)) return cfg.target;
  for (const a of cfg.args ?? []) {
    if (!a.startsWith('-') && existsSync(a)) return a;
  }
  return undefined;
}
