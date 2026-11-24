import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { McpToolDefinition } from '../types.js';

export interface TrustLockEntry {
  target: string;
  pinnedAt: string;
  tools: Record<string, { hash: string; description?: string }>;
}

export interface TrustLockFile {
  version: number;
  servers: Record<string, TrustLockEntry>;
}

export interface TrustDiff {
  isNew: boolean;
  added: string[];
  removed: string[];
  changed: Array<{
    name: string;
    previousHash: string;
    currentHash: string;
    previousDescription?: string;
    currentDescription?: string;
  }>;
  hasChanges: boolean;
}

export function hashToolDefinition(tool: McpToolDefinition): string {
  const canonical = stableStringify({
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? {},
    annotations: tool.annotations ?? {},
  });
  return createHash('sha256').update(canonical).digest('hex');
}

export function hashToolList(tools: McpToolDefinition[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tools) {
    out[t.name] = hashToolDefinition(t);
  }
  return out;
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

export class TrustLockStore {
  readonly filePath: string;

  constructor(baseDir?: string) {
    const dir = baseDir ?? process.env.MCPGUARD_HOME ?? join(homedir(), '.mcpguard');
    this.filePath = join(dir, 'trust.lock.json');
  }

  load(): TrustLockFile {
    if (!existsSync(this.filePath)) return { version: 1, servers: {} };
    try {
      const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as Partial<TrustLockFile>;
      return { version: parsed.version ?? 1, servers: parsed.servers ?? {} };
    } catch {
      return { version: 1, servers: {} };
    }
  }

  save(data: TrustLockFile): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(data, null, 2), 'utf8');
  }

  pin(serverKey: string, target: string, tools: McpToolDefinition[]): TrustLockEntry {
    const data = this.load();
    const map: Record<string, { hash: string; description?: string }> = {};
    for (const t of tools) {
      map[t.name] = {
        hash: hashToolDefinition(t),
        description: t.description?.slice(0, 300),
      };
    }
    const entry: TrustLockEntry = {
      target,
      pinnedAt: new Date().toISOString(),
      tools: map,
    };
    data.servers[serverKey] = entry;
    this.save(data);
    return entry;
  }

  diff(serverKey: string, currentTools: McpToolDefinition[]): TrustDiff {
    const data = this.load();
    const existing = data.servers[serverKey];
    if (!existing) {
      return { isNew: true, added: [], removed: [], changed: [], hasChanges: false };
    }

    const currentMap = new Map<string, McpToolDefinition>();
    for (const t of currentTools) currentMap.set(t.name, t);

    const added: string[] = [];
    const removed: string[] = [];
    const changed: TrustDiff['changed'] = [];

    for (const [name, tool] of currentMap.entries()) {
      const prev = existing.tools[name];
      const curHash = hashToolDefinition(tool);
      if (!prev) {
        added.push(name);
      } else if (prev.hash !== curHash) {
        changed.push({
          name,
          previousHash: prev.hash,
          currentHash: curHash,
          previousDescription: prev.description,
          currentDescription: tool.description?.slice(0, 300),
        });
      }
    }

    for (const prevName of Object.keys(existing.tools)) {
      if (!currentMap.has(prevName)) removed.push(prevName);
    }

    return {
      isNew: false,
      added,
      removed,
      changed,
      hasChanges: added.length > 0 || removed.length > 0 || changed.length > 0,
    };
  }
}
