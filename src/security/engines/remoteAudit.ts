import { randomUUID } from 'node:crypto';
import type {
  McpToolDefinition,
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';
import { discoverOAuthMetadata } from '../../auth/oauth.js';
import { hashToolList } from '../trustLock.js';
import { scanOutputForLeaksAndInjection } from '../runtimeGuard.js';

/**
 * External/Remote URL Security & Leak Evaluation Engine:
 * 1. HTTP/TLS/CORS/OAuth 2.1 posture audit
 * 2. Cloaking / Split-View detection (diffs tools/list SHA-256 across distinct clientInfo identities)
 * 3. Safe opt-in behavioral probing (--probe):
 *    - Schema validation error disclosure check (detects leaked stack traces, internal IPs, tokens)
 *    - Synthetic Canary token reflection & exfiltration-link check on readOnlyHint tools
 */
export const remoteAuditEngine: SecurityEngine = {
  id: 'remote-audit',
  name: 'Remote URL Posture, Cloaking & Leak Audit',
  requiresNetwork: true,
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    if (ctx.transport !== 'http' && ctx.transport !== 'sse' && ctx.transport !== 'urano-webhook') {
      return {
        engineId: 'remote-audit',
        engineName: 'Remote URL Posture, Cloaking & Leak Audit',
        status: 'skip',
        summary: 'Local stdio transport (remote HTTP posture check skipped)',
        findings: [],
      };
    }

    const findings: SecurityFinding[] = [];
    const oauthEndpoints: string[] = [];

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(ctx.target);
    } catch {
      return {
        engineId: 'remote-audit',
        engineName: 'Remote URL Posture, Cloaking & Leak Audit',
        status: 'warn',
        summary: 'Invalid target URL',
        findings: [],
      };
    }

    // 1. HTTPS & Punycode / IDN Homograph check
    const isLocal = parsedUrl.hostname === '127.0.0.1' || parsedUrl.hostname === 'localhost';
    if (parsedUrl.protocol === 'http:' && !isLocal) {
      findings.push({
        engine: 'remote-audit',
        ruleId: 'remote-plaintext-http',
        severity: 'high',
        title: 'Remote MCP uses unencrypted HTTP',
        detail: `Endpoint ${ctx.target} does not use HTTPS; tool payloads and tokens can be intercepted.`,
        target: ctx.target,
        remediation: 'Use an https:// endpoint.',
      });
    }
    if (parsedUrl.hostname.includes('xn--')) {
      findings.push({
        engine: 'remote-audit',
        ruleId: 'remote-punycode-domain',
        severity: 'medium',
        title: 'Punycode / IDN domain detected',
        detail: `Hostname "${parsedUrl.hostname}" uses Punycode (possible lookalike/homograph domain).`,
        target: parsedUrl.hostname,
      });
    }

    // 2. CORS & Redirect Posture Check (safe OPTIONS preflight)
    try {
      const optRes = await fetch(ctx.target, {
        method: 'OPTIONS',
        redirect: 'manual',
        headers: {
          origin: 'https://untrusted-origin.invalid',
          'access-control-request-method': 'POST',
        },
      });
      const acao = optRes.headers.get('access-control-allow-origin');
      const acac = optRes.headers.get('access-control-allow-credentials');
      if (acao === '*' && acac?.toLowerCase() === 'true') {
        findings.push({
          engine: 'remote-audit',
          ruleId: 'remote-cors-wildcard-creds',
          severity: 'high',
          title: 'Insecure CORS wildcard with credentials',
          detail: 'Server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.',
          target: ctx.target,
        });
      } else if (acao === 'https://untrusted-origin.invalid') {
        findings.push({
          engine: 'remote-audit',
          ruleId: 'remote-cors-origin-reflection',
          severity: 'medium',
          title: 'Permissive CORS origin reflection',
          detail: 'Server reflects arbitrary Origin headers, increasing cross-site / DNS-rebinding risk.',
          target: ctx.target,
        });
      }

      const location = optRes.headers.get('location');
      if (location && parsedUrl.protocol === 'https:' && location.startsWith('http://')) {
        findings.push({
          engine: 'remote-audit',
          ruleId: 'remote-https-downgrade',
          severity: 'critical',
          title: 'HTTPS-to-HTTP redirect downgrade',
          detail: `Endpoint redirects from HTTPS to plaintext HTTP (${location}).`,
          target: ctx.target,
        });
      }
    } catch {
      // Non-fatal if OPTIONS is not supported
    }

    // 3. OAuth 2.1 Discovery Posture
    try {
      const oauthMeta = await discoverOAuthMetadata(ctx.target);
      if (oauthMeta) {
        oauthEndpoints.push(oauthMeta.authorization_endpoint, oauthMeta.token_endpoint);
        const pkceMethods = oauthMeta.code_challenge_methods_supported ?? [];
        if (pkceMethods.length > 0 && !pkceMethods.includes('S256')) {
          findings.push({
            engine: 'remote-audit',
            ruleId: 'remote-oauth-no-pkce-s256',
            severity: 'medium',
            title: 'OAuth server does not advertise PKCE S256',
            detail: `Supported challenge methods: [${pkceMethods.join(', ')}].`,
            target: oauthMeta.authorization_endpoint,
          });
        }
      }
    } catch {
      // Optional metadata
    }

    // 4. Cloaking / Split-View Detection (compare tools/list across distinct clientInfo identities)
    if (ctx.checkCloaking !== false && ctx.transport === 'http') {
      try {
        const baselineHashes = hashToolList(ctx.tools);
        const probeTools = await fetchToolsWithIdentity(ctx.target, ctx.headers, {
          name: 'claude-desktop',
          version: '1.0.0',
        });
        if (probeTools) {
          const probeHashes = hashToolList(probeTools);
          const diffs: string[] = [];
          const allNames = new Set([...Object.keys(baselineHashes), ...Object.keys(probeHashes)]);
          for (const name of allNames) {
            if (baselineHashes[name] !== probeHashes[name]) {
              diffs.push(name);
            }
          }
          if (diffs.length > 0) {
            findings.push({
              engine: 'remote-audit',
              ruleId: 'remote-cloaking-split-view',
              severity: 'critical',
              title: 'Cloaking / Split-View attack detected!',
              detail: `Server returned DIFFERENT tool definitions when queried as "claude-desktop" vs "mcpguard" for tool(s): ${diffs.join(', ')}.`,
              target: ctx.target,
              remediation: 'Treat this remote MCP as malicious; it is serving different schemas depending on client identity.',
            });
          }
        }
      } catch {
        // Non-fatal if server requires sticky auth/session
      }
    }

    // 5. Safe Opt-In Behavioral Probe (--probe)
    if (ctx.probe && ctx.connector && ctx.tools.length > 0) {
      await runSafeBehavioralProbe(ctx, findings);
    }

    const hasCritOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    const status = hasCritOrHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass';

    return {
      engineId: 'remote-audit',
      engineName: 'Remote URL Posture, Cloaking & Leak Audit',
      status,
      summary:
        findings.length === 0
          ? `Remote URL posture clean${ctx.probe ? ' (including safe --probe)' : ''}`
          : `${findings.length} remote security/leak finding(s)`,
      findings,
      metadata: { oauthEndpoints },
    };
  },
};

async function fetchToolsWithIdentity(
  url: string,
  headers: Record<string, string> | undefined,
  clientInfo: { name: string; version: string },
): Promise<McpToolDefinition[] | null> {
  const baseHeaders: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
    ...headers,
  };

  const initRes = await fetch(url, {
    method: 'POST',
    headers: baseHeaders,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo },
    }),
  });
  if (!initRes.ok) return null;
  const sid = initRes.headers.get('mcp-session-id');
  if (sid) baseHeaders['mcp-session-id'] = sid;

  const listRes = await fetch(url, {
    method: 'POST',
    headers: baseHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
  });
  if (!listRes.ok) return null;
  const ct = listRes.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) return null;
  const body = (await listRes.json()) as { result?: { tools?: McpToolDefinition[] } };
  return body.result?.tools ?? null;
}

async function runSafeBehavioralProbe(
  ctx: SecurityScanContext,
  findings: SecurityFinding[],
): Promise<void> {
  if (!ctx.connector) return;

  // 5a. Safe schema-validation error disclosure test (empty args on a tool with required params)
  const toolWithReq = ctx.tools.find(
    (t) => Array.isArray(t.inputSchema?.required) && t.inputSchema!.required.length > 0,
  );
  if (toolWithReq) {
    try {
      const res = await ctx.connector.callTool(toolWithReq.name, {});
      const text = res.content.map((c) => c.text ?? '').join('\n');
      inspectErrorDisclosure(text, `probe:${toolWithReq.name}`, findings);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      inspectErrorDisclosure(msg, `probe:${toolWithReq.name}`, findings);
    }
  }

  // 5b. Synthetic Canary probe ONLY on tools explicitly annotated readOnlyHint: true
  const readOnlyTool = ctx.tools.find((t) => t.annotations?.readOnlyHint === true);
  if (readOnlyTool) {
    const canary = `mcpguard-canary-${randomUUID().slice(0, 8)}`;
    const args: Record<string, unknown> = {};
    const props = readOnlyTool.inputSchema?.properties ?? {};
    for (const reqKey of readOnlyTool.inputSchema?.required ?? []) {
      const prop = props[reqKey];
      args[reqKey] = prop?.type === 'number' || prop?.type === 'integer' ? 1 : canary;
    }

    try {
      const res = await ctx.connector.callTool(readOnlyTool.name, args);
      const outputFindings = scanOutputForLeaksAndInjection(res, `probe:${readOnlyTool.name}`, canary);
      findings.push(...outputFindings);
    } catch {
      // Ignore if read-only tool rejects synthetic input
    }
  }
}

function inspectErrorDisclosure(text: string, target: string, findings: SecurityFinding[]): void {
  if (!text) return;
  if (/at\s+\S+\s+\((?:\/|[A-Z]:\\)[^)]+:\d+:\d+\)/i.test(text)) {
    findings.push({
      engine: 'remote-audit',
      ruleId: 'probe-stacktrace-leak',
      severity: 'low',
      title: 'Server error leaks internal stack trace / file paths',
      detail: `Validation error from ${target} exposed internal runtime stack trace.`,
      target,
      evidence: text.slice(0, 140),
    });
  }
  if (/(postgres|mongodb|mysql|redis):\/\/[^\s'"]+|169\.254\.169\.254|(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})/i.test(text)) {
    findings.push({
      engine: 'remote-audit',
      ruleId: 'probe-secret-or-metadata-leak',
      severity: 'critical',
      title: 'Server response leaks credentials, DB URI, or cloud metadata IP',
      detail: `Error response from ${target} disclosed sensitive backend internals.`,
      target,
    });
  }
}
