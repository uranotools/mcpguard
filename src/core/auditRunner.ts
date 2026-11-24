import type {
  AuditSuite,
  AuditSuiteReport,
  AuditTestResult,
  McpGuardContext,
  McpToolDefinition,
  SecurityReport,
} from '../types.js';
import { NATIVE_CONTEXT_KEYS } from './context.js';

/**
 * Runs AuditSuites against an already-populated McpGuardContext so audit tests
 * reuse captured MCP tools, security reports, architecture data, and plugin exports
 * without reconnecting.
 */
export class AuditRunner {
  private readonly suites = new Map<string, AuditSuite>();

  constructor(includeBuiltIns = true) {
    if (includeBuiltIns) {
      for (const suite of getBuiltInAuditSuites()) {
        this.register(suite);
      }
    }
  }

  register(suite: AuditSuite): void {
    this.suites.set(suite.id, suite);
  }

  get(id: string): AuditSuite | undefined {
    return this.suites.get(id);
  }

  list(): AuditSuite[] {
    return Array.from(this.suites.values());
  }

  async runSuite(suiteOrId: string | AuditSuite, ctx: McpGuardContext): Promise<AuditSuiteReport> {
    const suite = typeof suiteOrId === 'string' ? this.suites.get(suiteOrId) : suiteOrId;
    if (!suite) {
      throw new Error(`Unknown audit suite: "${String(suiteOrId)}"`);
    }

    const start = Date.now();
    const results: AuditTestResult[] = [];

    for (const testCase of suite.tests) {
      try {
        const outcome = await testCase.run(ctx);
        results.push({
          id: testCase.id,
          title: testCase.title,
          passed: outcome.passed,
          severity: testCase.severity ?? 'medium',
          detail: outcome.detail,
          data: outcome.data,
        });
      } catch (err) {
        results.push({
          id: testCase.id,
          title: testCase.title,
          passed: false,
          severity: testCase.severity ?? 'high',
          detail: `Audit test threw an error: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }

    const passed = results.filter((r) => r.passed).length;
    const report: AuditSuiteReport = {
      suiteId: suite.id,
      suiteName: suite.name,
      passed,
      failed: results.length - passed,
      total: results.length,
      results,
      durationMs: Date.now() - start,
    };

    ctx.publish(`audit.${suite.id}`, report, 'auditRunner');
    return report;
  }
}

export function getBuiltInAuditSuites(): AuditSuite[] {
  return [
    {
      id: 'owasp-mcp',
      name: 'OWASP MCP Baseline Audit',
      description: 'Validates tool metadata hygiene, prompt injection resilience, and privilege boundaries using captured MCP context.',
      tests: [
        {
          id: 'mcp-has-tools',
          title: 'Server exposes valid tool definitions',
          severity: 'info',
          async run(ctx) {
            const tools = ctx.get<McpToolDefinition[]>(NATIVE_CONTEXT_KEYS.TOOLS) ?? [];
            return {
              passed: tools.length > 0,
              detail: tools.length > 0
                ? `Discovered ${tools.length} tool(s).`
                : 'No tools were discovered from this MCP server.',
              data: { count: tools.length },
            };
          },
        },
        {
          id: 'mcp-no-high-poisoning',
          title: 'Zero critical/high security findings in scan report',
          severity: 'critical',
          async run(ctx) {
            const report = ctx.get<SecurityReport>(NATIVE_CONTEXT_KEYS.SECURITY_REPORT);
            if (!report) {
              return { passed: false, detail: 'Security report not present in context.' };
            }
            const bad = report.findings.filter(
              (f) => f.severity === 'critical' || f.severity === 'high',
            );
            return {
              passed: bad.length === 0,
              detail:
                bad.length === 0
                  ? `Security score ${report.score}/100 (${report.verdict}).`
                  : `Found ${bad.length} high/critical finding(s): ${bad.map((b) => b.ruleId).join(', ')}`,
              data: { score: report.score, verdict: report.verdict, badCount: bad.length },
            };
          },
        },
        {
          id: 'mcp-tool-descriptions-present',
          title: 'All tools provide clear, bounded descriptions',
          severity: 'low',
          async run(ctx) {
            const tools = ctx.get<McpToolDefinition[]>(NATIVE_CONTEXT_KEYS.TOOLS) ?? [];
            const missing = tools.filter((t) => !t.description || t.description.trim().length < 5);
            const bloated = tools.filter((t) => (t.description?.length ?? 0) > 4000);
            const ok = missing.length === 0 && bloated.length === 0;
            return {
              passed: ok,
              detail: ok
                ? `All ${tools.length} tools have concise descriptions.`
                : `Missing descriptions: ${missing.length}; oversized (>4KB): ${bloated.length}.`,
              data: {
                missing: missing.map((t) => t.name),
                bloated: bloated.map((t) => t.name),
              },
            };
          },
        },
      ],
    },
    {
      id: 'privacy',
      name: 'Privacy & Egress Hygiene Audit',
      description: 'Checks outbound URLs, environment variable access, and parameter smuggling indicators.',
      tests: [
        {
          id: 'privacy-outbound-urls',
          title: 'Outbound URLs use HTTPS',
          severity: 'medium',
          async run(ctx) {
            const urls = ctx.get<string[]>(NATIVE_CONTEXT_KEYS.OUTBOUND_URLS) ?? [];
            const insecure = urls.filter((u) => u.startsWith('http://') && !u.includes('127.0.0.1') && !u.includes('localhost'));
            return {
              passed: insecure.length === 0,
              detail:
                insecure.length === 0
                  ? `Checked ${urls.length} outbound URL(s); none use plaintext remote HTTP.`
                  : `Detected ${insecure.length} plaintext HTTP URL(s): ${insecure.slice(0, 3).join(', ')}`,
              data: { insecure },
            };
          },
        },
        {
          id: 'privacy-sensitive-env',
          title: 'No suspicious access to unrelated secret env vars',
          severity: 'high',
          async run(ctx) {
            const envVars = ctx.get<string[]>(NATIVE_CONTEXT_KEYS.ENV_VARS) ?? [];
            const sensitive = envVars.filter((v) =>
              /AWS_SECRET|SSH_|PRIVATE_KEY|NPM_TOKEN|GITHUB_TOKEN|STRIPE_SECRET/i.test(v),
            );
            return {
              passed: sensitive.length === 0,
              detail:
                sensitive.length === 0
                  ? `Inspected ${envVars.length} env var reference(s); no sensitive credential reads flagged.`
                  : `Code references sensitive env vars: ${sensitive.join(', ')}`,
              data: { sensitive },
            };
          },
        },
      ],
    },
  ];
}
