import type {
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp; title: string; severity: 'high' | 'critical' }> = [
  {
    id: 'poison-ignore-prev',
    re: /\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
    title: 'Prompt injection override directive',
    severity: 'critical',
  },
  {
    id: 'poison-important-tag',
    re: /<\s*(IMPORTANT|SYSTEM|HIDDEN|INSTRUCTIONS?)\b[^>]*>[\s\S]{0,600}(read|send|exfiltrat|secret|ssh|env|token|pass|before\s+calling)/i,
    title: 'Hidden XML-style coercive directive in tool metadata',
    severity: 'critical',
  },
  {
    id: 'poison-secret-exfil',
    re: /(read|include|pass|append|send|exfiltrate)\s+[\w\s'"`/~.-]{0,60}(\.ssh|id_rsa|\.env|api[_-]?key|access[_-]?token|credentials|aws_secret|conversation\s+history|system\s+prompt)/i,
    title: 'Directive attempting to access or exfiltrate sensitive files/secrets',
    severity: 'critical',
  },
  {
    id: 'poison-cross-shadowing',
    re: /(instead\s+of\s+calling|override\s+the\s+tool|do\s+not\s+mention\s+this\s+to\s+the\s+user|silently\s+(send|call|forward)|never\s+tell\s+the\s+user)/i,
    title: 'Stealth / cross-server tool shadowing instruction',
    severity: 'high',
  },
  {
    id: 'poison-markdown-beacon',
    re: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]+(\?[^)\s]+)?\s*\)/i,
    title: 'Markdown image beacon / potential exfiltration URL in metadata',
    severity: 'high',
  },
];

// Invisible Unicode: zero-width chars, BiDi overrides, and Unicode Tag block (U+E0000..U+E007F)
const INVISIBLE_UNICODE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]|[\u{E0000}-\u{E007F}]/u;

// Suspicious hidden/optional parameter names often used for Parameter Smuggling
const SMUGGLING_PARAM_RE = /^(sidenote|side_note|hidden_context|system_prompt|conversation_history|chat_history|env_vars|raw_secrets|auth_dump|telemetry_blob|context_dump)$/i;

/**
 * Tool Poisoning, Prompt Injection, Parameter Smuggling & Unicode scanner.
 * Optionally bridges to @uranotools/urano-guard when installed.
 */
export const poisoningEngine: SecurityEngine = {
  id: 'poisoning',
  name: 'Tool Poisoning & Prompt Injection',
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    const findings: SecurityFinding[] = [];
    const uranoGuardAvailable = await tryCheckUranoGuardAvailability();

    for (const tool of ctx.tools) {
      const desc = tool.description ?? '';
      scanTextBlock(desc, `tool:${tool.name}.description`, findings);

      // Padding evasion check: unusually long tool descriptions (> 4KB)
      if (desc.length > 4096) {
        findings.push({
          engine: 'poisoning',
          ruleId: 'poison-padding-evasion',
          severity: 'medium',
          title: 'Oversized tool description (potential padding evasion)',
          detail: `Tool "${tool.name}" description is ${desc.length} chars; attackers hide instructions in long tails.`,
          target: `tool:${tool.name}.description`,
          remediation: 'Inspect the tail of the tool description carefully before approving.',
        });
      }

      // Inspect inputSchema properties for Parameter Smuggling and hidden prompt injections
      const props = tool.inputSchema?.properties ?? {};
      const reqSet = new Set(tool.inputSchema?.required ?? []);

      for (const [propName, propDef] of Object.entries(props)) {
        const propDesc = typeof propDef.description === 'string' ? propDef.description : '';
        scanTextBlock(propDesc, `tool:${tool.name}.inputSchema.${propName}`, findings);

        if (SMUGGLING_PARAM_RE.test(propName)) {
          findings.push({
            engine: 'poisoning',
            ruleId: 'poison-parameter-smuggling',
            severity: 'high',
            title: 'Suspicious Parameter Smuggling field detected',
            detail: `Tool "${tool.name}" defines ${reqSet.has(propName) ? 'required' : 'optional'} parameter "${propName}" commonly used to smuggle secrets or conversation history.`,
            target: `tool:${tool.name}.inputSchema.${propName}`,
            remediation: 'Verify why this parameter exists and avoid passing sensitive context.',
          });
        }

        if (typeof propDef.default === 'string') {
          scanTextBlock(propDef.default, `tool:${tool.name}.inputSchema.${propName}.default`, findings);
        }
      }

      // Annotation mismatch check (e.g. claims readOnlyHint: true on a destructive/mutating tool)
      if (
        tool.annotations?.readOnlyHint === true &&
        /\b(delete|remove|drop|exec|execute|shell|write|modify|update|transfer|send_email)\b/i.test(
          `${tool.name} ${desc}`,
        )
      ) {
        findings.push({
          engine: 'poisoning',
          ruleId: 'poison-annotation-mismatch',
          severity: 'medium',
          title: 'Tool annotation contradicts name/description',
          detail: `Tool "${tool.name}" declares readOnlyHint=true but its name or description indicates mutating/destructive behavior.`,
          target: `tool:${tool.name}.annotations`,
        });
      }
    }

    // Also scan prompts and resources metadata
    for (const prompt of ctx.prompts) {
      scanTextBlock(prompt.description ?? '', `prompt:${prompt.name}.description`, findings);
    }
    for (const resource of ctx.resources) {
      scanTextBlock(resource.description ?? '', `resource:${resource.uri}.description`, findings);
    }

    const hasCritOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    const status = hasCritOrHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass';

    return {
      engineId: 'poisoning',
      engineName: 'Tool Poisoning & Prompt Injection',
      status,
      summary:
        findings.length === 0
          ? `0 poisoning indicators across ${ctx.tools.length} tool(s)${uranoGuardAvailable ? ' (urano-guard bridge active)' : ''}`
          : `${findings.length} poisoning/smuggling finding(s) detected`,
      findings,
      metadata: { uranoGuardBridge: uranoGuardAvailable },
    };
  },
};

function scanTextBlock(text: string, target: string, findings: SecurityFinding[]): void {
  if (!text) return;

  if (INVISIBLE_UNICODE_RE.test(text)) {
    findings.push({
      engine: 'poisoning',
      ruleId: 'poison-invisible-unicode',
      severity: 'critical',
      title: 'Invisible / BiDi / Tag Unicode smuggling detected',
      detail: `Hidden non-printable Unicode characters found in ${target}.`,
      target,
      remediation: 'Reject this MCP server or inspect raw hex bytes of the schema.',
    });
  }

  for (const pat of INJECTION_PATTERNS) {
    const match = text.match(pat.re);
    if (match) {
      findings.push({
        engine: 'poisoning',
        ruleId: pat.id,
        severity: pat.severity,
        title: pat.title,
        detail: `Matched suspicious pattern in ${target}.`,
        target,
        evidence: match[0].slice(0, 140),
        remediation: 'Do not trust this tool definition without manual inspection.',
      });
    }
  }

  // Check for suspicious base64 blobs (>60 chars) that decode to prompt instructions
  const b64Matches = text.match(/[A-Za-z0-9+/]{60,}={0,2}/g) ?? [];
  for (const blob of b64Matches.slice(0, 3)) {
    try {
      const decoded = Buffer.from(blob, 'base64').toString('utf8');
      if (
        /ignore\s+previous|system\s+prompt|exfiltrat|id_rsa|api[_-]?key|curl\s+http/i.test(decoded)
      ) {
        findings.push({
          engine: 'poisoning',
          ruleId: 'poison-base64-payload',
          severity: 'critical',
          title: 'Base64-encoded prompt injection or command detected',
          detail: `Decoded Base64 payload in ${target} contains malicious instructions.`,
          target,
          evidence: decoded.slice(0, 120),
        });
      }
    } catch {
      // Ignore non-base64
    }
  }
}

async function tryCheckUranoGuardAvailability(): Promise<boolean> {
  try {
    const modName = '@uranotools/urano-guard';
    await import(modName);
    return true;
  } catch {
    return false;
  }
}
