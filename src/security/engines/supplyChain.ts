import type {
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';
import { NATIVE_CONTEXT_KEYS } from '../../core/context.js';

const POPULAR_OFFICIAL_MCP_PACKAGES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-fetch',
];

export interface ThreatFeedDocument {
  blockedDomains?: string[];
  blockedPackages?: string[];
  blockedHashes?: string[];
}

export const supplyChainEngine: SecurityEngine = {
  id: 'supply-chain',
  name: 'Supply Chain, OSV.dev & Threat Feeds',
  requiresNetwork: true,
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    const findings: SecurityFinding[] = [];
    const pkgName = extractNpmPackageFromStdio(ctx.command, ctx.args);

    // 1. Typosquatting heuristic for npm MCP packages
    if (pkgName) {
      for (const official of POPULAR_OFFICIAL_MCP_PACKAGES) {
        if (pkgName !== official && levenshtein(pkgName, official) <= 2) {
          findings.push({
            engine: 'supply-chain',
            ruleId: 'supply-typosquatting',
            severity: 'high',
            title: 'Possible typosquatted MCP package name',
            detail: `Package "${pkgName}" is suspiciously close to official package "${official}".`,
            target: pkgName,
            remediation: `Verify that you intended "${pkgName}" and not "${official}".`,
          });
        }
      }
    }

    // 2. Query OSV.dev for known vulnerabilities (free, no API key)
    if (pkgName && process.env.MCPGUARD_OFFLINE !== '1') {
      try {
        const osvRes = await fetch('https://api.osv.dev/v1/query', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ package: { name: pkgName, ecosystem: 'npm' } }),
        });
        if (osvRes.ok) {
          const data = (await osvRes.json()) as { vulns?: Array<{ id: string; summary?: string }> };
          const vulns = data.vulns ?? [];
          for (const v of vulns.slice(0, 5)) {
            findings.push({
              engine: 'supply-chain',
              ruleId: `osv-${v.id}`,
              severity: 'high',
              title: `Known vulnerability ${v.id} in ${pkgName}`,
              detail: v.summary ?? 'Reported in OSV.dev vulnerability database.',
              target: pkgName,
            });
          }
        }
      } catch {
        // Non-fatal offline/network error
      }
    }

    // 3. Check pluggable external JSON Threat Feeds (IOC blocklists)
    const domainsToCheck = new Set<string>(
      ctx.contextStore?.get<string[]>(NATIVE_CONTEXT_KEYS.OUTBOUND_DOMAINS) ?? [],
    );
    try {
      if (ctx.target.startsWith('http://') || ctx.target.startsWith('https://')) {
        domainsToCheck.add(new URL(ctx.target).hostname);
      }
    } catch {
      // ignore
    }

    for (const feedUrl of ctx.threatFeeds ?? []) {
      try {
        const res = await fetch(feedUrl);
        if (!res.ok) continue;
        const feed = (await res.json()) as ThreatFeedDocument;
        for (const d of domainsToCheck) {
          if (feed.blockedDomains?.includes(d)) {
            findings.push({
              engine: 'supply-chain',
              ruleId: 'threat-feed-domain-hit',
              severity: 'critical',
              title: 'Domain matched external threat feed blocklist',
              detail: `Domain "${d}" is listed in threat feed ${feedUrl}.`,
              target: d,
            });
          }
        }
        if (pkgName && feed.blockedPackages?.includes(pkgName)) {
          findings.push({
            engine: 'supply-chain',
            ruleId: 'threat-feed-package-hit',
            severity: 'critical',
            title: 'Package matched external threat feed blocklist',
            detail: `Package "${pkgName}" is listed in threat feed ${feedUrl}.`,
            target: pkgName,
          });
        }
      } catch {
        // Ignore unreachable feed
      }
    }

    const hasCritOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    return {
      engineId: 'supply-chain',
      engineName: 'Supply Chain, OSV.dev & Threat Feeds',
      status: hasCritOrHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass',
      summary:
        findings.length === 0
          ? `0 CVEs / blocklist hits${pkgName ? ` (${pkgName})` : ''}`
          : `${findings.length} supply-chain/reputation finding(s)`,
      findings,
    };
  },
};

export function extractNpmPackageFromStdio(command?: string, args?: string[]): string | undefined {
  if (!command || !args || args.length === 0) return undefined;
  if (!/^(npx|pnpx|bunx|npm)$/i.test(command)) return undefined;
  for (const a of args) {
    if (a.startsWith('-')) continue;
    // Strip @version suffix except leading scope @org/pkg
    const stripped = a.replace(/^(@[^/]+\/[^@]+|[^@]+)@.+$/, '$1');
    return stripped;
  }
  return undefined;
}

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}
