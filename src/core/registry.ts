import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type {
  ConfiguredProvider,
  HistoryEntry,
  McpGuardConfigFile,
  McpServerConfig,
  SavedPreset,
  SecurityPolicy,
} from '../types.js';
import { SecretVault } from './vault.js';

const DEFAULT_CONFIG: McpGuardConfigFile = {
  version: 1,
  securityPolicy: 'warn',
  threatFeeds: [],
  servers: {},
  providers: {},
  presets: {},
};

export class ConfigRegistry {
  readonly baseDir: string;
  readonly configPath: string;
  readonly historyPath: string;
  readonly vault: SecretVault;

  constructor(baseDir?: string) {
    this.baseDir = baseDir ?? process.env.MCPGUARD_HOME ?? join(homedir(), '.mcpguard');
    this.configPath = join(this.baseDir, 'config.json');
    this.historyPath = join(this.baseDir, 'history.json');
    this.vault = new SecretVault(this.baseDir);
  }

  load(): McpGuardConfigFile {
    if (!existsSync(this.configPath)) {
      return structuredClone(DEFAULT_CONFIG);
    }
    try {
      const parsed = JSON.parse(readFileSync(this.configPath, 'utf8')) as Partial<McpGuardConfigFile>;
      return {
        version: parsed.version ?? 1,
        defaultProvider: parsed.defaultProvider,
        securityPolicy: parsed.securityPolicy ?? 'warn',
        threatFeeds: parsed.threatFeeds ?? [],
        servers: parsed.servers ?? {},
        providers: parsed.providers ?? {},
        presets: parsed.presets ?? {},
      };
    } catch {
      return structuredClone(DEFAULT_CONFIG);
    }
  }

  save(cfg: McpGuardConfigFile): void {
    mkdirSync(this.baseDir, { recursive: true });
    writeFileSync(this.configPath, JSON.stringify(cfg, null, 2), 'utf8');
  }

  // --- Servers ---

  getServer(name: string): McpServerConfig | undefined {
    return this.load().servers[name];
  }

  listServers(): McpServerConfig[] {
    return Object.values(this.load().servers);
  }

  upsertServer(server: McpServerConfig): void {
    const cfg = this.load();
    cfg.servers[server.name] = server;
    this.save(cfg);
  }

  removeServer(name: string): boolean {
    const cfg = this.load();
    if (!cfg.servers[name]) return false;
    const secretRef = cfg.servers[name].secretRef;
    delete cfg.servers[name];
    this.save(cfg);
    if (secretRef) this.vault.delete(secretRef);
    return true;
  }

  // --- Providers ---

  getProvider(id?: string): ConfiguredProvider | undefined {
    const cfg = this.load();
    const targetId = id ?? cfg.defaultProvider;
    if (!targetId) return undefined;
    return cfg.providers[targetId];
  }

  listProviders(): { defaultProvider?: string; providers: ConfiguredProvider[] } {
    const cfg = this.load();
    return {
      defaultProvider: cfg.defaultProvider,
      providers: Object.values(cfg.providers),
    };
  }

  upsertProvider(provider: ConfiguredProvider, makeDefault = false): void {
    const cfg = this.load();
    cfg.providers[provider.id] = provider;
    if (makeDefault || !cfg.defaultProvider) {
      cfg.defaultProvider = provider.id;
    }
    this.save(cfg);
  }

  setDefaultProvider(id: string): boolean {
    const cfg = this.load();
    if (!cfg.providers[id]) return false;
    cfg.defaultProvider = id;
    this.save(cfg);
    return true;
  }

  removeProvider(id: string): boolean {
    const cfg = this.load();
    if (!cfg.providers[id]) return false;
    const secretRef = cfg.providers[id].secretRef;
    delete cfg.providers[id];
    if (cfg.defaultProvider === id) {
      cfg.defaultProvider = Object.keys(cfg.providers)[0];
    }
    this.save(cfg);
    if (secretRef) this.vault.delete(secretRef);
    return true;
  }

  // --- Presets ---

  savePreset(preset: SavedPreset): void {
    const cfg = this.load();
    cfg.presets[preset.alias] = preset;
    this.save(cfg);
  }

  getPreset(alias: string): SavedPreset | undefined {
    return this.load().presets[alias];
  }

  listPresets(): SavedPreset[] {
    return Object.values(this.load().presets);
  }

  removePreset(alias: string): boolean {
    const cfg = this.load();
    if (!cfg.presets[alias]) return false;
    delete cfg.presets[alias];
    this.save(cfg);
    return true;
  }

  // --- Policy ---

  setSecurityPolicy(policy: SecurityPolicy): void {
    const cfg = this.load();
    cfg.securityPolicy = policy;
    this.save(cfg);
  }

  // --- History ---

  appendHistory(entry: HistoryEntry): void {
    mkdirSync(this.baseDir, { recursive: true });
    const list = this.listHistory();
    list.unshift(entry);
    const trimmed = list.slice(0, 100);
    writeFileSync(this.historyPath, JSON.stringify(trimmed, null, 2), 'utf8');
  }

  listHistory(): HistoryEntry[] {
    if (!existsSync(this.historyPath)) return [];
    try {
      return JSON.parse(readFileSync(this.historyPath, 'utf8')) as HistoryEntry[];
    } catch {
      return [];
    }
  }
}
