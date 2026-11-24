import type {
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';

/**
 * Optional VirusTotal API v3 integration for remote MCP URL/domain reputation.
 * Enabled automatically when VT_API_KEY env var or --vt-key flag is provided.
 */
export const virusTotalEngine: SecurityEngine = {
  id: 'virustotal',
  name: 'VirusTotal API v3 Reputation',
  requiresNetwork: true,
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    const apiKey = ctx.vtApiKey ?? process.env.VT_API_KEY;
    if (!apiKey) {
      return {
        engineId: 'virustotal',
        engineName: 'VirusTotal API v3 Reputation',
        status: 'skip',
        summary: 'Skipped (set VT_API_KEY or pass --vt-key to enable)',
        findings: [],
      };
    }

    if (!ctx.target.startsWith('http://') && !ctx.target.startsWith('https://')) {
      return {
        engineId: 'virustotal',
        engineName: 'VirusTotal API v3 Reputation',
        status: 'skip',
        summary: 'Skipped (target is not an HTTP/HTTPS URL)',
        findings: [],
      };
    }

    const findings: SecurityFinding[] = [];
    const baseUrl = process.env.MCPGUARD_VT_BASE_URL ?? 'https://www.virustotal.com/api/v3';
    const urlId = Buffer.from(ctx.target).toString('base64url');

    try {
      const res = await fetch(`${baseUrl}/urls/${urlId}`, {
        headers: { 'x-apikey': apiKey },
      });

      if (res.status === 404) {
        return {
          engineId: 'virustotal',
          engineName: 'VirusTotal API v3 Reputation',
          status: 'pass',
          summary: 'URL not previously flagged in VirusTotal',
          findings: [],
        };
      }

      if (!res.ok) {
        return {
          engineId: 'virustotal',
          engineName: 'VirusTotal API v3 Reputation',
          status: 'warn',
          summary: `VirusTotal API returned HTTP ${res.status}`,
          findings: [],
        };
      }

      const data = (await res.json()) as {
        data?: {
          attributes?: {
            last_analysis_stats?: {
              malicious?: number;
              suspicious?: number;
              harmless?: number;
            };
          };
        };
      };
      const stats = data.data?.attributes?.last_analysis_stats ?? {};
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;

      if (malicious > 0) {
        findings.push({
          engine: 'virustotal',
          ruleId: 'vt-url-malicious',
          severity: 'critical',
          title: `VirusTotal flagged URL as malicious (${malicious} engine(s))`,
          detail: `Malicious=${malicious}, Suspicious=${suspicious}, Harmless=${stats.harmless ?? 0}`,
          target: ctx.target,
        });
      } else if (suspicious > 0) {
        findings.push({
          engine: 'virustotal',
          ruleId: 'vt-url-suspicious',
          severity: 'medium',
          title: `VirusTotal flagged URL as suspicious (${suspicious} engine(s))`,
          detail: `Suspicious=${suspicious}, Harmless=${stats.harmless ?? 0}`,
          target: ctx.target,
        });
      }

      return {
        engineId: 'virustotal',
        engineName: 'VirusTotal API v3 Reputation',
        status: malicious > 0 ? 'fail' : suspicious > 0 ? 'warn' : 'pass',
        summary: `malicious=${malicious}, suspicious=${suspicious}, harmless=${stats.harmless ?? 0}`,
        findings,
        metadata: { stats },
      };
    } catch (err) {
      return {
        engineId: 'virustotal',
        engineName: 'VirusTotal API v3 Reputation',
        status: 'skip',
        summary: `VirusTotal unreachable: ${err instanceof Error ? err.message : String(err)}`,
        findings: [],
      };
    }
  },
};
