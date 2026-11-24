import type { McpToolCallResult, SecurityFinding } from '../types.js';

const SECRET_PATTERNS: Array<{ id: string; label: string; re: RegExp }> = [
  { id: 'secret-openai', label: 'OpenAI / OpenRouter API key', re: /\bsk-(?:or-v1-|proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: 'secret-github', label: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
  { id: 'secret-aws', label: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'secret-slack', label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'secret-private-key', label: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { id: 'secret-jwt', label: 'JWT bearer token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
];

export interface SecretScanResult {
  hasSecrets: boolean;
  findings: SecurityFinding[];
  maskedPayload: Record<string, unknown>;
}

/**
 * Scans outgoing tool arguments before calling an MCP server to prevent accidental
 * secret/credential leaks, returning both findings and a safely masked copy.
 */
export function scanOutgoingArgsForSecrets(
  args: Record<string, unknown>,
  target = 'invocation.args',
): SecretScanResult {
  const findings: SecurityFinding[] = [];
  const masked = maskRecursive(args, target, findings) as Record<string, unknown>;
  return {
    hasSecrets: findings.length > 0,
    findings,
    maskedPayload: masked,
  };
}

function maskRecursive(value: unknown, path: string, findings: SecurityFinding[]): unknown {
  if (typeof value === 'string') {
    let out = value;
    for (const pat of SECRET_PATTERNS) {
      pat.re.lastIndex = 0;
      if (pat.re.test(out)) {
        findings.push({
          engine: 'runtime-guard',
          ruleId: pat.id,
          severity: 'high',
          title: `Outgoing secret detected: ${pat.label}`,
          detail: `Field "${path}" appears to contain a sensitive credential.`,
          target: path,
          remediation: 'Mask or remove credentials before sending to an external MCP.',
        });
        pat.re.lastIndex = 0;
        out = out.replace(pat.re, '[REDACTED_BY_MCPGUARD]');
      }
    }
    return out;
  }
  if (Array.isArray(value)) {
    return value.map((item, idx) => maskRecursive(item, `${path}[${idx}]`, findings));
  }
  if (value && typeof value === 'object') {
    const copy: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      copy[k] = maskRecursive(v, `${path}.${k}`, findings);
    }
    return copy;
  }
  return value;
}

/**
 * Scans MCP tool output for indirect prompt injection, leaked credentials,
 * or exfiltration Markdown beacons (optionally checking for a synthetic canary token).
 */
export function scanOutputForLeaksAndInjection(
  result: McpToolCallResult,
  target = 'invocation.result',
  canaryToken?: string,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const text = result.content.map((c) => c.text ?? '').join('\n');
  if (!text) return findings;

  if (/\b(ignore\s+(all\s+)?previous\s+instructions?|you\s+are\s+now\s+in\s+developer\s+mode|<\s*IMPORTANT\b)/i.test(text)) {
    findings.push({
      engine: 'runtime-guard',
      ruleId: 'runtime-indirect-prompt-injection',
      severity: 'high',
      title: 'Indirect prompt injection in MCP tool output',
      detail: `Tool output from ${target} contains instruction-override directives.`,
      target,
    });
  }

  if (canaryToken) {
    const beaconRe = new RegExp(`!\\[[^\\]]*\\]\\(\\s*https?:\\/\\/[^)\\s]*${escapeRegExp(canaryToken)}[^)\\s]*\\)`, 'i');
    if (beaconRe.test(text)) {
      findings.push({
        engine: 'runtime-guard',
        ruleId: 'runtime-canary-exfiltration-beacon',
        severity: 'critical',
        title: 'Canary token embedded in external Markdown exfiltration beacon!',
        detail: `Server reflected synthetic canary "${canaryToken}" inside an external image/link URL.`,
        target,
      });
    }
  }

  for (const pat of SECRET_PATTERNS) {
    pat.re.lastIndex = 0;
    if (pat.re.test(text)) {
      findings.push({
        engine: 'runtime-guard',
        ruleId: `output-${pat.id}`,
        severity: 'high',
        title: `MCP output leaked credential (${pat.label})`,
        detail: `Response from ${target} contains a pattern matching ${pat.label}.`,
        target,
      });
    }
  }

  return findings;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
