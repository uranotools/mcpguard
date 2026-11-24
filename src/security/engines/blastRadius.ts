import type {
  McpToolDefinition,
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';

export type ToolRiskClass = 'read' | 'write' | 'destructive' | 'exec' | 'network';

export function classifyToolRisk(tool: McpToolDefinition): ToolRiskClass {
  const text = `${tool.name} ${tool.description ?? ''}`;
  if (/\b(exec|execute|shell|bash|powershell|cmd|spawn|run_command|eval|terminal)\b/i.test(text)) {
    return 'exec';
  }
  if (
    tool.annotations?.destructiveHint === true ||
    /\b(delete|remove|drop|destroy|purge|wipe|terminate|kill|revoke)\b/i.test(text)
  ) {
    return 'destructive';
  }
  if (/\b(write|create|update|edit|patch|put|post|upload|send|publish|deploy|commit|push|transfer)\b/i.test(text)) {
    return 'write';
  }
  if (/\b(fetch|http|request|curl|webhook|browse|scrape|download|url)\b/i.test(text)) {
    return 'network';
  }
  return 'read';
}

const DANGEROUS_STDIO_RE = /(curl\s+.*\|\s*(sh|bash)|--privileged|rm\s+-rf|--dangerously|--no-sandbox)/i;
const BROAD_OAUTH_SCOPE_RE = /^(\*|admin|root|write:all|full_access|repo|delete_repo)$/i;

export const blastRadiusEngine: SecurityEngine = {
  id: 'blast-radius',
  name: 'Blast Radius & Permissions',
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    const findings: SecurityFinding[] = [];
    const counts: Record<ToolRiskClass, number> = {
      read: 0,
      write: 0,
      destructive: 0,
      exec: 0,
      network: 0,
    };

    for (const tool of ctx.tools) {
      const risk = classifyToolRisk(tool);
      counts[risk]++;
      if (risk === 'exec') {
        findings.push({
          engine: 'blast-radius',
          ruleId: 'blast-shell-exec',
          severity: 'high',
          title: 'Arbitrary command/shell execution capability',
          detail: `Tool "${tool.name}" appears to execute shell/OS commands.`,
          target: `tool:${tool.name}`,
          remediation: 'Require explicit confirmation (--yes disabled) and restrict environment.',
        });
      } else if (risk === 'destructive') {
        findings.push({
          engine: 'blast-radius',
          ruleId: 'blast-destructive-tool',
          severity: 'medium',
          title: 'Destructive tool capability',
          detail: `Tool "${tool.name}" can delete or permanently alter resources.`,
          target: `tool:${tool.name}`,
        });
      }
    }

    // Audit stdio command line
    if (ctx.transport === 'stdio' && ctx.command) {
      const fullCmd = [ctx.command, ...(ctx.args ?? [])].join(' ');
      if (DANGEROUS_STDIO_RE.test(fullCmd)) {
        findings.push({
          engine: 'blast-radius',
          ruleId: 'blast-dangerous-stdio-cmd',
          severity: 'critical',
          title: 'Dangerous local stdio launch command',
          detail: `Command "${fullCmd}" matches unsafe execution flags or piped shell patterns.`,
          target: 'stdio:command',
        });
      }
    }

    // Audit OAuth scopes
    for (const scope of ctx.oauthScopes ?? []) {
      if (BROAD_OAUTH_SCOPE_RE.test(scope)) {
        findings.push({
          engine: 'blast-radius',
          ruleId: 'blast-overprivileged-scope',
          severity: 'high',
          title: 'Overly broad OAuth scope requested',
          detail: `Server requests high-privilege OAuth scope "${scope}".`,
          target: `oauth:scope:${scope}`,
          remediation: 'Limit scopes with --scope to least-privilege access.',
        });
      }
    }

    const hasCritOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    const status = hasCritOrHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass';

    return {
      engineId: 'blast-radius',
      engineName: 'Blast Radius & Permissions',
      status,
      summary: `Tools by risk: exec=${counts.exec}, destructive=${counts.destructive}, write=${counts.write}, net=${counts.network}, read=${counts.read}`,
      findings,
      metadata: { counts },
    };
  },
};
