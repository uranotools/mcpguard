import type {
  CodeInspectionSummary,
  MetaDispatcherSummary,
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityPolicy,
  SecurityReport,
  SecurityScanContext,
  SecuritySeverity,
  SecurityVerdict,
  ToolAuditDetail,
} from '../types.js';
import { NATIVE_CONTEXT_KEYS } from '../core/context.js';
import { buildToolForm } from '../core/schemaForm.js';
import { buildArchitectureSummary } from './architectureReport.js';
import { blastRadiusEngine, classifyToolRisk } from './engines/blastRadius.js';
import { codeInspectorEngine } from './engines/codeInspector.js';
import { metaDispatcherEngine } from './engines/metaDispatcher.js';
import { poisoningEngine } from './engines/poisoning.js';
import { remoteAuditEngine } from './engines/remoteAudit.js';
import { semanticAiEngine } from './engines/semanticAi.js';
import { supplyChainEngine } from './engines/supplyChain.js';
import { tlsNetworkEngine } from './engines/tlsNetwork.js';
import { virusTotalEngine } from './engines/virustotal.js';
import { hashToolList, TrustLockStore } from './trustLock.js';

export { hashToolDefinition, hashToolList, TrustLockStore } from './trustLock.js';
export type { TrustDiff, TrustLockEntry, TrustLockFile } from './trustLock.js';
export { poisoningEngine } from './engines/poisoning.js';
export { blastRadiusEngine, classifyToolRisk } from './engines/blastRadius.js';
export { metaDispatcherEngine } from './engines/metaDispatcher.js';
export { codeInspectorEngine, inspectLocalMcpCode } from './engines/codeInspector.js';
export { remoteAuditEngine } from './engines/remoteAudit.js';
export { supplyChainEngine, extractNpmPackageFromStdio } from './engines/supplyChain.js';
export { tlsNetworkEngine } from './engines/tlsNetwork.js';
export type { TlsNetworkTelemetry } from './engines/tlsNetwork.js';
export { virusTotalEngine } from './engines/virustotal.js';
export { semanticAiEngine } from './engines/semanticAi.js';
export { scanOutgoingArgsForSecrets, scanOutputForLeaksAndInjection } from './runtimeGuard.js';
export {
  buildArchitectureSummary,
  renderArchitectureMermaid,
  renderMarkdownSecurityReport,
} from './architectureReport.js';

export interface RunSecurityScanOptions {
  extraEngines?: SecurityEngine[];
  trustLockStore?: TrustLockStore;
  skipNetworkEngines?: boolean;
  /** Restrict scan to specific engine IDs or short aliases (e.g. ['tls', 'meta', 'poisoning']). */
  onlyEngines?: string[];
  onEngineStart?: (index: number, total: number, engineName: string) => void;
  onEngineDone?: (index: number, total: number, result: SecurityEngineResult) => void;
}

const ENGINE_ALIASES: Record<string, string> = {
  lock: 'trust-lock',
  trust: 'trust-lock',
  poison: 'poisoning',
  blast: 'blast-radius',
  meta: 'meta-dispatcher',
  code: 'code-inspector',
  tls: 'tls-network',
  net: 'tls-network',
  headers: 'tls-network',
  remote: 'remote-audit',
  cloaking: 'remote-audit',
  supply: 'supply-chain',
  osv: 'supply-chain',
  vt: 'virustotal',
  ai: 'semantic-ai',
};

function normalizeEngineFilter(only?: string[]): Set<string> | null {
  if (!only || only.length === 0) return null;
  const set = new Set<string>();
  for (const raw of only) {
    for (const part of raw.split(',')) {
      const clean = part.trim().toLowerCase();
      if (!clean) continue;
      set.add(ENGINE_ALIASES[clean] ?? clean);
    }
  }
  return set.size > 0 ? set : null;
}

const SEVERITY_DEDUCTION: Record<SecuritySeverity, number> = {
  info: 0,
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
};

/**
 * VirusTotal-for-MCP Multi-Engine Security Orchestrator.
 * Runs all normalized engines + Rug Pull lockfile check, computes a 0-100 score & verdict,
 * builds the inferred architecture summary, and publishes results into ContextStore.
 */
export async function runSecurityScan(
  ctx: SecurityScanContext,
  opts: RunSecurityScanOptions = {},
): Promise<SecurityReport> {
  const scanStart = Date.now();
  const filterSet = normalizeEngineFilter(opts.onlyEngines);

  const allEngines: SecurityEngine[] = [
    poisoningEngine,
    blastRadiusEngine,
    metaDispatcherEngine,
    codeInspectorEngine,
    tlsNetworkEngine,
    remoteAuditEngine,
    supplyChainEngine,
    virusTotalEngine,
    semanticAiEngine,
    ...(opts.extraEngines ?? []),
  ];
  const engines = filterSet ? allEngines.filter((e) => filterSet.has(e.id)) : allEngines;
  const runTrustLock = Boolean(ctx.serverName) && (!filterSet || filterSet.has('trust-lock'));

  const totalEngines = engines.length + (runTrustLock ? 1 : 0);
  let stepIdx = 0;

  const engineResults: SecurityEngineResult[] = [];
  const allFindings: SecurityFinding[] = [];
  let codeInspection: CodeInspectionSummary | undefined;
  let networkTelemetry: Record<string, unknown> | undefined;
  let metaDispatcher: MetaDispatcherSummary | undefined;
  let oauthEndpoints: string[] = [];

  // 1. Rug Pull Lockfile check if serverName is known
  const lockStore = opts.trustLockStore ?? new TrustLockStore();
  if (runTrustLock && ctx.serverName) {
    stepIdx++;
    const t0 = Date.now();
    opts.onEngineStart?.(stepIdx, totalEngines, 'Rug Pull SHA-256 Trust Lockfile');
    const diff = lockStore.diff(ctx.serverName, ctx.tools);
    const lockFindings: SecurityFinding[] = [];
    if (diff.changed.length > 0) {
      for (const ch of diff.changed) {
        lockFindings.push({
          engine: 'trust-lock',
          ruleId: 'rug-pull-tool-mutated',
          severity: 'critical',
          title: `Possible Rug Pull: tool "${ch.name}" changed since pinning`,
          detail: `SHA-256 changed from ${ch.previousHash.slice(0, 12)} to ${ch.currentHash.slice(0, 12)}.`,
          target: `tool:${ch.name}`,
          remediation: 'Run "mcpguard trust diff <name>" to review changes and "mcpguard trust approve <name>" only if expected.',
        });
      }
    }
    if (diff.added.length > 0) {
      lockFindings.push({
        engine: 'trust-lock',
        ruleId: 'rug-pull-tools-added',
        severity: 'medium',
        title: `New unpinned tool(s) appeared: ${diff.added.join(', ')}`,
        detail: 'Server added tools after initial pinning.',
      });
    }
    const lockRes: SecurityEngineResult = {
      engineId: 'trust-lock',
      engineName: 'Rug Pull SHA-256 Trust Lockfile',
      status: diff.changed.length > 0 ? 'fail' : diff.added.length > 0 ? 'warn' : 'pass',
      durationMs: Date.now() - t0,
      summary: diff.isNew
        ? `New server (${ctx.tools.length} tool(s) ready to pin)`
        : diff.hasChanges
          ? `Drift detected: changed=${diff.changed.length}, added=${diff.added.length}, removed=${diff.removed.length}`
          : `All ${ctx.tools.length} pinned tool hashes match`,
      findings: lockFindings,
    };
    engineResults.push(lockRes);
    allFindings.push(...lockFindings);
    opts.onEngineDone?.(stepIdx, totalEngines, lockRes);
  }

  // 2. Run all security engines
  for (const engine of engines) {
    stepIdx++;
    const t0 = Date.now();
    opts.onEngineStart?.(stepIdx, totalEngines, engine.name);

    if (opts.skipNetworkEngines && engine.requiresNetwork) {
      const skippedRes: SecurityEngineResult = {
        engineId: engine.id,
        engineName: engine.name,
        status: 'skip',
        durationMs: 0,
        summary: 'Skipped (offline mode)',
        findings: [],
      };
      engineResults.push(skippedRes);
      opts.onEngineDone?.(stepIdx, totalEngines, skippedRes);
      continue;
    }

    const res = await engine.analyze(ctx);
    res.durationMs = Date.now() - t0;
    engineResults.push(res);
    allFindings.push(...res.findings);
    opts.onEngineDone?.(stepIdx, totalEngines, res);

    if (res.metadata?.codeInspection) {
      codeInspection = res.metadata.codeInspection as CodeInspectionSummary;
    }
    if (res.metadata?.tlsNetwork) {
      networkTelemetry = res.metadata.tlsNetwork as Record<string, unknown>;
    }
    if (res.metadata?.metaDispatcher) {
      metaDispatcher = res.metadata.metaDispatcher as MetaDispatcherSummary;
    }
    if (Array.isArray(res.metadata?.oauthEndpoints)) {
      oauthEndpoints = res.metadata.oauthEndpoints as string[];
    }
  }

  // 3. Aggregate score & VirusTotal-style verdict
  let score = 100;
  for (const f of allFindings) {
    score -= SEVERITY_DEDUCTION[f.severity];
  }
  score = Math.max(0, Math.min(100, score));

  const hasCritical = allFindings.some((f) => f.severity === 'critical');
  const hasHigh = allFindings.some((f) => f.severity === 'high');
  const hasMedium = allFindings.some((f) => f.severity === 'medium');

  let verdict: SecurityVerdict = 'CLEAN';
  if (hasCritical || score < 40) verdict = 'MALICIOUS';
  else if (hasHigh || score < 70) verdict = 'SUSPICIOUS';
  else if (hasMedium || score < 90) verdict = 'WARN';

  const enginesSkipped = engineResults.filter((e) => e.status === 'skip').length;
  const enginesRun = engineResults.length - enginesSkipped;
  const enginesFlagged = engineResults.filter((e) => e.status === 'fail' || e.status === 'warn').length;
  const toolHashes = hashToolList(ctx.tools);

  const architecture = buildArchitectureSummary({
    target: ctx.target,
    transport: ctx.transport,
    serverInfo: ctx.serverInfo,
    tools: ctx.tools,
    codeInspection,
    oauthEndpoints,
  });

  const toolsDetail: ToolAuditDetail[] = ctx.tools.map((t) => {
    const form = buildToolForm(t);
    const toolFindings = allFindings.filter(
      (f) => f.target === `tool:${t.name}` || f.target?.startsWith(`tool:${t.name}.`),
    );
    return {
      name: t.name,
      description: t.description,
      descriptionChars: t.description?.length ?? 0,
      risk: classifyToolRisk(t),
      hash: toolHashes[t.name] ?? '',
      annotations: t.annotations,
      params: form.steps.map((s) => ({
        name: s.name,
        type: s.type,
        required: s.required,
        section: s.section,
        description: s.description,
        enumValues: s.enumValues,
      })),
      findingCount: toolFindings.length,
    };
  });

  const report: SecurityReport = {
    target: ctx.target,
    verdict,
    score,
    durationMs: Date.now() - scanStart,
    enginesRun,
    enginesFlagged,
    enginesSkipped,
    engineResults,
    findings: allFindings,
    toolHashes,
    toolsDetail,
    metaDispatcher,
    architecture,
    codeInspection,
    networkTelemetry,
    timestamp: new Date().toISOString(),
  };

  // Publish into ContextStore so AuditSuites, FlagAdapters, and CLI commands reuse it
  ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.TOOL_HASHES, toolHashes);
  ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.SECURITY_REPORT, report);
  ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.ARCHITECTURE, architecture);

  return report;
}

export function isBlockedByPolicy(verdict: SecurityVerdict, policy: SecurityPolicy): boolean {
  if (policy === 'off') return false;
  if (policy === 'strict') return verdict !== 'CLEAN';
  // Default 'warn' policy blocks MALICIOUS automatically
  return verdict === 'MALICIOUS';
}
