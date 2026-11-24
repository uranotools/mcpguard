import { resolve4, resolve6 } from 'node:dns/promises';
import { connect as tlsConnect } from 'node:tls';
import type {
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';

export interface TlsNetworkTelemetry {
  hostname: string;
  port: number;
  resolvedIps: string[];
  tlsProtocol?: string;
  tlsCipher?: string;
  certSubject?: string;
  certIssuer?: string;
  certValidTo?: string;
  certDaysRemaining?: number;
  serverHeader?: string;
  missingSecurityHeaders: string[];
  presentSecurityHeaders: string[];
  unauthStatus?: number;
  unauthProtected?: boolean;
}

const PRIVATE_IP_RE = /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fc|fd|fe80)/i;

/**
 * Auditor-grade Network, TLS/X.509 Certificate, DNS, HTTP Security Headers,
 * and Unauthenticated Access (Broken Auth) inspection engine for remote MCP URLs.
 */
export const tlsNetworkEngine: SecurityEngine = {
  id: 'tls-network',
  name: 'TLS/X.509, DNS, Headers & Auth Gate',
  requiresNetwork: true,
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    if (!ctx.target.startsWith('http://') && !ctx.target.startsWith('https://')) {
      return {
        engineId: 'tls-network',
        engineName: 'TLS/X.509, DNS, Headers & Auth Gate',
        status: 'skip',
        summary: 'Local stdio transport (no network endpoint)',
        findings: [],
      };
    }

    let parsed: URL;
    try {
      parsed = new URL(ctx.target);
    } catch {
      return {
        engineId: 'tls-network',
        engineName: 'TLS/X.509, DNS, Headers & Auth Gate',
        status: 'warn',
        summary: 'Invalid URL',
        findings: [],
      };
    }

    const findings: SecurityFinding[] = [];
    const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
    const isLocalHost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';

    const telemetry: TlsNetworkTelemetry = {
      hostname: parsed.hostname,
      port,
      resolvedIps: [],
      missingSecurityHeaders: [],
      presentSecurityHeaders: [],
    };

    // 1. DNS Resolution & SSRF / DNS-Rebinding check
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname) && !isLocalHost) {
      const [v4, v6] = await Promise.all([
        resolve4(parsed.hostname).catch(() => [] as string[]),
        resolve6(parsed.hostname).catch(() => [] as string[]),
      ]);
      telemetry.resolvedIps = [...v4, ...v6];
      const privateHits = telemetry.resolvedIps.filter((ip) => PRIVATE_IP_RE.test(ip));
      if (privateHits.length > 0) {
        findings.push({
          engine: 'tls-network',
          ruleId: 'net-dns-rebinding-private-ip',
          severity: 'high',
          title: 'External hostname resolves to private/internal IP (DNS rebinding / SSRF risk)',
          detail: `${parsed.hostname} resolved to private address(es): ${privateHits.join(', ')}.`,
          target: parsed.hostname,
          remediation: 'Verify DNS records and block private IP ranges on external MCP gateways.',
        });
      }
    } else {
      telemetry.resolvedIps = [parsed.hostname];
    }

    // 2. Real TLS / X.509 Certificate Inspection (HTTPS endpoints)
    if (parsed.protocol === 'https:') {
      const tlsInfo = await inspectTlsCertificate(parsed.hostname, port);
      if (tlsInfo.error) {
        findings.push({
          engine: 'tls-network',
          ruleId: 'tls-handshake-warning',
          severity: 'medium',
          title: 'TLS inspection warning',
          detail: tlsInfo.error,
          target: `${parsed.hostname}:${port}`,
        });
      } else {
        telemetry.tlsProtocol = tlsInfo.protocol;
        telemetry.tlsCipher = tlsInfo.cipher;
        telemetry.certSubject = tlsInfo.subject;
        telemetry.certIssuer = tlsInfo.issuer;
        telemetry.certValidTo = tlsInfo.validTo;
        telemetry.certDaysRemaining = tlsInfo.daysRemaining;

        if (tlsInfo.protocol && /^TLSv1(\.0|\.1)?$/i.test(tlsInfo.protocol)) {
          findings.push({
            engine: 'tls-network',
            ruleId: 'tls-deprecated-protocol',
            severity: 'high',
            title: `Deprecated TLS protocol negotiated (${tlsInfo.protocol})`,
            detail: `Endpoint negotiated ${tlsInfo.protocol}; TLS 1.2 or TLS 1.3 is required.`,
            target: parsed.hostname,
          });
        }
        if (tlsInfo.daysRemaining !== undefined && tlsInfo.daysRemaining < 15) {
          findings.push({
            engine: 'tls-network',
            ruleId: 'tls-cert-expiring',
            severity: tlsInfo.daysRemaining < 0 ? 'critical' : 'medium',
            title:
              tlsInfo.daysRemaining < 0
                ? 'TLS certificate is EXPIRED'
                : `TLS certificate expires in ${tlsInfo.daysRemaining} day(s)`,
            detail: `Certificate valid_to: ${tlsInfo.validTo ?? 'unknown'} (Issuer: ${tlsInfo.issuer ?? 'unknown'}).`,
            target: parsed.hostname,
          });
        }
      }
    }

    // 3. Unauthenticated Access Check + HTTP Security Headers Audit
    try {
      const unauthRes = await fetch(ctx.target, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 999, method: 'tools/list', params: {} }),
      });

      telemetry.unauthStatus = unauthRes.status;
      telemetry.unauthProtected = unauthRes.status === 401 || unauthRes.status === 403;

      if (unauthRes.status === 200) {
        const ct = unauthRes.headers.get('content-type') ?? '';
        if (ct.includes('application/json')) {
          const body = (await unauthRes.json().catch(() => null)) as { result?: { tools?: unknown[] } } | null;
          if (Array.isArray(body?.result?.tools) && body.result.tools.length > 0 && !isLocalHost) {
            findings.push({
              engine: 'tls-network',
              ruleId: 'auth-unauthenticated-tools-exposed',
              severity: 'medium',
              title: 'MCP tools/list accessible without authentication',
              detail: `Unauthenticated POST returned HTTP 200 with ${body.result.tools.length} tool(s). Confirm if public anonymous access is intentional.`,
              target: ctx.target,
              remediation: 'Require OAuth 2.1 or Bearer authentication unless this is an intentionally public read-only MCP.',
            });
          }
        }
      }

      const serverHdr = unauthRes.headers.get('server') ?? unauthRes.headers.get('x-powered-by');
      if (serverHdr) telemetry.serverHeader = serverHdr;

      const desiredHeaders = [
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'content-security-policy',
      ];
      for (const h of desiredHeaders) {
        if (unauthRes.headers.get(h)) telemetry.presentSecurityHeaders.push(h);
        else telemetry.missingSecurityHeaders.push(h);
      }

      if (parsed.protocol === 'https:' && !unauthRes.headers.get('strict-transport-security')) {
        findings.push({
          engine: 'tls-network',
          ruleId: 'http-missing-hsts',
          severity: 'low',
          title: 'Missing Strict-Transport-Security (HSTS) header',
          detail: `HTTPS endpoint ${parsed.hostname} did not send Strict-Transport-Security.`,
          target: ctx.target,
          remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.',
        });
      }
    } catch {
      // Non-fatal network check error
    }

    const hasCritOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    const status = hasCritOrHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass';

    const parts: string[] = [];
    if (telemetry.tlsProtocol) parts.push(telemetry.tlsProtocol);
    if (telemetry.certDaysRemaining !== undefined) parts.push(`cert ${telemetry.certDaysRemaining}d left`);
    if (telemetry.unauthStatus) {
      parts.push(telemetry.unauthProtected ? `auth enforced (${telemetry.unauthStatus})` : `unauth HTTP ${telemetry.unauthStatus}`);
    }
    if (telemetry.resolvedIps.length > 0) parts.push(`IP ${telemetry.resolvedIps[0]}`);

    return {
      engineId: 'tls-network',
      engineName: 'TLS/X.509, DNS, Headers & Auth Gate',
      status,
      summary: parts.length > 0 ? parts.join(' · ') : 'Network posture inspected',
      findings,
      metadata: { tlsNetwork: telemetry },
    };
  },
};

function inspectTlsCertificate(
  host: string,
  port: number,
): Promise<{
  protocol?: string;
  cipher?: string;
  subject?: string;
  issuer?: string;
  validTo?: string;
  daysRemaining?: number;
  error?: string;
}> {
  return new Promise((resolve) => {
    const socket = tlsConnect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: 6000 },
      () => {
        try {
          const protocol = socket.getProtocol() ?? undefined;
          const cipher = socket.getCipher()?.name;
          const cert = socket.getPeerCertificate();
          const validTo = cert?.valid_to;
          let daysRemaining: number | undefined;
          if (validTo) {
            const expMs = Date.parse(validTo);
            if (!Number.isNaN(expMs)) {
              daysRemaining = Math.floor((expMs - Date.now()) / (1000 * 60 * 60 * 24));
            }
          }
          const rawSubj = cert?.subject?.CN;
          const rawIssuer = cert?.issuer?.O ?? cert?.issuer?.CN;
          resolve({
            protocol,
            cipher,
            subject: Array.isArray(rawSubj) ? rawSubj[0] : rawSubj,
            issuer: Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer,
            validTo,
            daysRemaining,
          });
        } catch (err) {
          resolve({ error: err instanceof Error ? err.message : String(err) });
        } finally {
          socket.end();
        }
      },
    );
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ error: 'TLS handshake timed out' });
    });
    socket.on('error', (err) => {
      resolve({ error: err.message });
    });
  });
}
