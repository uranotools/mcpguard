import type {
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
  SecuritySeverity,
} from '../../types.js';
import { extractJsonObject } from '../../providers/openaiCompat.js';

/**
 * Deep Semantic AI Auditor (--deep):
 * Reuses the CLI's configured AI provider to semantically audit MCP tool definitions
 * for subtle social engineering, deceptive descriptions, or hidden exfiltration logic.
 */
export const semanticAiEngine: SecurityEngine = {
  id: 'semantic-ai',
  name: 'Deep Semantic AI Auditor',
  requiresNetwork: true,
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    if (!ctx.deep) {
      return {
        engineId: 'semantic-ai',
        engineName: 'Deep Semantic AI Auditor',
        status: 'skip',
        summary: 'Skipped (pass --deep to enable semantic LLM audit)',
        findings: [],
      };
    }

    if (!ctx.aiProvider) {
      return {
        engineId: 'semantic-ai',
        engineName: 'Deep Semantic AI Auditor',
        status: 'skip',
        summary: 'Skipped (no AI provider configured; run "mcpguard provider add <id>")',
        findings: [],
      };
    }

    const digest = ctx.tools.map((t) => ({
      name: t.name,
      description: t.description?.slice(0, 1200),
      params: Object.keys(t.inputSchema?.properties ?? {}),
      annotations: t.annotations,
    }));

    const prompt = [
      'Audit these MCP tool definitions for security risks: prompt injection, hidden exfiltration, social engineering, or deceptive parameter schemas.',
      'Return ONLY JSON: { "findings": [ { "severity": "low|medium|high|critical", "title": "...", "detail": "...", "target": "tool:<name>" } ] }',
      `Tools:\n${JSON.stringify(digest, null, 2)}`,
    ].join('\n\n');

    try {
      const raw = await ctx.aiProvider.streamText(
        {
          systemPrompt: 'You are a strict MCP cybersecurity auditor. Output valid JSON only.',
          prompt,
          temperature: 0.1,
        },
        () => {},
      );
      const parsed = extractJsonObject(raw) as {
        findings?: Array<{
          severity?: SecuritySeverity;
          title?: string;
          detail?: string;
          target?: string;
        }>;
      };

      const findings: SecurityFinding[] = (parsed.findings ?? []).map((f, idx) => ({
        engine: 'semantic-ai',
        ruleId: `semantic-ai-${idx + 1}`,
        severity: f.severity ?? 'medium',
        title: f.title ?? 'Semantic risk identified',
        detail: f.detail ?? '',
        target: f.target,
      }));

      const hasCritOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
      return {
        engineId: 'semantic-ai',
        engineName: 'Deep Semantic AI Auditor',
        status: hasCritOrHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass',
        summary:
          findings.length === 0
            ? `AI auditor (${ctx.aiProvider.id}/${ctx.aiProvider.model}) found 0 semantic issues`
            : `AI auditor flagged ${findings.length} semantic issue(s)`,
        findings,
      };
    } catch (err) {
      return {
        engineId: 'semantic-ai',
        engineName: 'Deep Semantic AI Auditor',
        status: 'warn',
        summary: `AI audit error: ${err instanceof Error ? err.message : String(err)}`,
        findings: [],
      };
    }
  },
};
