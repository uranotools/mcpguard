import type {
  ArchitectureSummary,
  CodeInspectionSummary,
  McpServerInfo,
  McpToolDefinition,
  SecurityReport,
  TransportKind,
} from '../types.js';
import { classifyToolRisk } from './engines/blastRadius.js';
import { hashToolDefinition } from './trustLock.js';

export function buildArchitectureSummary(params: {
  target: string;
  transport: TransportKind;
  serverInfo?: McpServerInfo;
  tools: McpToolDefinition[];
  codeInspection?: CodeInspectionSummary;
  oauthEndpoints?: string[];
}): ArchitectureSummary {
  const isLocalInspected = Boolean(params.codeInspection);
  const toolsByRisk = params.tools.map((t) => ({
    name: t.name,
    risk: classifyToolRisk(t),
    hash: hashToolDefinition(t).slice(0, 12),
    annotations: t.annotations,
  }));

  const notes: string[] = [];
  if (isLocalInspected) {
    notes.push(
      `Local source inspected (${params.codeInspection!.filesScanned} file(s)): outbound URLs, env vars, and OS primitives reflect static analysis evidence.`,
    );
  } else {
    notes.push(
      'Remote black-box MCP: backend source code and internal API calls are NOT observable over HTTP. Architecture reflects protocol surface, TLS/OAuth metadata, and observable tool schemas.',
    );
  }

  return {
    target: params.target,
    mode: isLocalInspected ? 'local-inspected' : 'remote-blackbox',
    transport: params.transport,
    serverInfo: params.serverInfo,
    toolCount: params.tools.length,
    toolsByRisk,
    outboundUrls: params.codeInspection?.outboundUrls ?? [],
    outboundDomains: params.codeInspection?.outboundDomains ?? [],
    envVars: params.codeInspection?.envVars ?? [],
    osCapabilities: params.codeInspection?.capabilities ?? [],
    oauthEndpoints: params.oauthEndpoints ?? [],
    notes,
  };
}

export function renderArchitectureMermaid(arch: ArchitectureSummary): string {
  const lines: string[] = ['flowchart LR'];
  lines.push(`  CLI["mcpguard CLI"] -->|${arch.transport}| MCP["${sanitizeLabel(arch.serverInfo?.name ?? arch.target)}"]`);

  const shownTools = arch.toolsByRisk.slice(0, 12);
  shownTools.forEach((t, idx) => {
    lines.push(`  MCP --> T${idx}["${sanitizeLabel(t.name)} (${t.risk})"]`);
  });
  if (arch.toolsByRisk.length > shownTools.length) {
    lines.push(`  MCP --> TMORE["+${arch.toolsByRisk.length - shownTools.length} more tools"]`);
  }

  if (arch.mode === 'local-inspected') {
    arch.outboundDomains.slice(0, 10).forEach((d, idx) => {
      lines.push(`  MCP -->|outbound| D${idx}["${sanitizeLabel(d)}"]`);
    });
    if (arch.envVars.length > 0) {
      lines.push(`  ENV["Env Vars: ${sanitizeLabel(arch.envVars.slice(0, 6).join(', '))}"] -.-> MCP`);
    }
    if (arch.osCapabilities.length > 0) {
      lines.push(`  MCP -->|OS| OS["${sanitizeLabel(arch.osCapabilities.join(', '))}"]`);
    }
  } else {
    lines.push('  MCP -.-> BB["Remote Backend (Black Box - Not Observable)"]');
    (arch.oauthEndpoints ?? []).slice(0, 2).forEach((ep, idx) => {
      lines.push(`  CLI -.->|OAuth| OA${idx}["${sanitizeLabel(ep)}"]`);
    });
  }

  return lines.join('\n');
}

export function renderMarkdownSecurityReport(report: SecurityReport): string {
  const out: string[] = [];
  out.push(`# MCPGuard Security & Architecture Report`);
  out.push('');
  out.push(`- **Target:** \`${report.target}\``);
  out.push(`- **Verdict:** **${report.verdict}** (Score: **${report.score}/100**)`);
  out.push(`- **Engines:** ${report.enginesFlagged} / ${report.enginesRun} flagged (${report.enginesSkipped} skipped)`);
  out.push(`- **Generated:** ${report.timestamp}`);
  out.push('');

  out.push('## Engine Breakdown');
  out.push('');
  out.push('| Engine | Status | Summary |');
  out.push('|---|---|---|');
  for (const e of report.engineResults) {
    out.push(`| ${e.engineName} | \`${e.status.toUpperCase()}\` | ${e.summary.replace(/\|/g, '\\|')} |`);
  }
  out.push('');

  if (report.findings.length > 0) {
    out.push('## Security Findings');
    out.push('');
    for (const f of report.findings) {
      out.push(`- **[${f.severity.toUpperCase()}] ${f.title}** (\`${f.engine}/${f.ruleId}\`)`);
      out.push(`  - ${f.detail}`);
      if (f.evidence) out.push(`  - Evidence: \`${f.evidence}\``);
      if (f.remediation) out.push(`  - Remediation: ${f.remediation}`);
    }
    out.push('');
  }

  if (report.architecture) {
    out.push('## Inferred Architecture');
    out.push('');
    for (const note of report.architecture.notes) {
      out.push(`> ${note}`);
    }
    out.push('');
    out.push('```mermaid');
    out.push(renderArchitectureMermaid(report.architecture));
    out.push('```');
    out.push('');

    if (report.architecture.toolsByRisk.length > 0) {
      out.push('### Tool Inventory & SHA-256 Pinning');
      out.push('');
      out.push('| Tool | Risk | SHA-256 (prefix) |');
      out.push('|---|---|---|');
      for (const t of report.architecture.toolsByRisk) {
        out.push(`| \`${t.name}\` | \`${t.risk}\` | \`${t.hash}\` |`);
      }
      out.push('');
    }
  }

  if (report.codeInspection && report.codeInspection.evidence.length > 0) {
    out.push('## Local Code Evidence (`file:line`)');
    out.push('');
    out.push('| Kind | Value | Location |');
    out.push('|---|---|---|');
    for (const ev of report.codeInspection.evidence.slice(0, 40)) {
      out.push(`| \`${ev.kind}\` | \`${ev.value.replace(/\|/g, '\\|')}\` | \`${ev.file}:${ev.line}\` |`);
    }
    out.push('');
  }

  return out.join('\n');
}

function sanitizeLabel(text: string): string {
  return text.replace(/["[\]]/g, '').slice(0, 60);
}
