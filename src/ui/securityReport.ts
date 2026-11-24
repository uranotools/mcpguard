import type { AuditSuiteReport, SecurityReport, SecurityVerdict } from '../types.js';
import type { TlsNetworkTelemetry } from '../security/engines/tlsNetwork.js';
import { ansi } from './ansi.js';

function colorVerdict(v: SecurityVerdict): string {
  switch (v) {
    case 'CLEAN':
      return ansi.green(ansi.bold(v));
    case 'WARN':
      return ansi.yellow(ansi.bold(v));
    case 'SUSPICIOUS':
      return ansi.magenta(ansi.bold(v));
    case 'MALICIOUS':
      return ansi.red(ansi.bold(v));
  }
}

function badge(status: 'pass' | 'warn' | 'fail' | 'skip'): string {
  switch (status) {
    case 'pass':
      return ansi.green('[PASS]');
    case 'warn':
      return ansi.yellow('[WARN]');
    case 'fail':
      return ansi.red('[FAIL]');
    case 'skip':
      return ansi.gray('[SKIP]');
  }
}

export interface FormatSecurityReportOptions {
  detail?: boolean;
  group?: string; // filter by risk group: exec | destructive | write | network | read
  section?: string; // zoom into one section: engines | tls | tools | meta | findings | arch | all
}

const RISK_GROUP_ORDER: Array<'exec' | 'destructive' | 'write' | 'network' | 'read'> = [
  'exec',
  'destructive',
  'write',
  'network',
  'read',
];

export function formatSecurityReportTerminal(
  report: SecurityReport,
  opts: FormatSecurityReportOptions = {},
): string {
  const lines: string[] = [];
  const bar = '─'.repeat(74);
  const dur = report.durationMs !== undefined ? `  |  ${report.durationMs}ms` : '';

  lines.push(ansi.cyan(`┌${bar}┐`));
  lines.push(`  ${ansi.bold('MCPGuard Security Audit')} — ${ansi.dim(report.target)}`);
  lines.push(
    `  Verdict: ${colorVerdict(report.verdict)}  |  Score: ${ansi.bold(`${report.score}/100`)}  |  ${report.enginesFlagged}/${report.enginesRun} engines flagged${ansi.dim(dur)}`,
  );
  lines.push(ansi.cyan(`└${bar}┘`));

  const secFilter = opts.section?.toLowerCase();
  const show = (name: string) => !secFilter || secFilter === 'all' || secFilter === name;

  // 1. Engine Breakdown with per-engine timing
  if (show('engines')) {
    for (const e of report.engineResults) {
      const ms = e.durationMs !== undefined ? ansi.dim(`${String(e.durationMs).padStart(4)}ms`) : '      ';
      lines.push(`  ${badge(e.status)} ${ms}  ${ansi.bold(e.engineName.padEnd(40))} ${e.summary}`);
    }
  }

  // 2. Network, TLS/X.509 & HTTP Security Posture Telemetry (Auditor detail)
  const net = report.networkTelemetry as TlsNetworkTelemetry | undefined;
  if (net && (show('tls') || show('headers') || show('network'))) {
    lines.push('');
    lines.push(ansi.bold('TLS / Network / Auth Posture:'));
    if (net.resolvedIps?.length) {
      lines.push(`  DNS / IP:          ${net.hostname} → ${net.resolvedIps.join(', ')}`);
    }
    if (net.tlsProtocol) {
      lines.push(
        `  TLS / Cipher:      ${ansi.green(net.tlsProtocol)} (${net.tlsCipher ?? 'standard'})`,
      );
    }
    if (net.certIssuer || net.certValidTo) {
      const expColor =
        net.certDaysRemaining !== undefined && net.certDaysRemaining < 15 ? ansi.yellow : ansi.green;
      lines.push(
        `  Certificate:       Issuer="${net.certIssuer ?? 'n/a'}" · Expires=${net.certValidTo ?? 'n/a'} (${expColor(`${net.certDaysRemaining ?? '?'}d left`)})`,
      );
    }
    if (net.unauthStatus !== undefined) {
      const gateStr = net.unauthProtected
        ? ansi.green(`ENFORCED (HTTP ${net.unauthStatus})`)
        : ansi.yellow(`OPEN (HTTP ${net.unauthStatus})`);
      lines.push(`  Unauth Gate:       ${gateStr}`);
    }
    if (net.serverHeader) {
      lines.push(`  Server Header:     ${ansi.dim(net.serverHeader)}`);
    }
    if (net.presentSecurityHeaders?.length) {
      lines.push(`  Sec Headers OK:    ${ansi.green(net.presentSecurityHeaders.join(', '))}`);
    }
    if (net.missingSecurityHeaders?.length) {
      lines.push(`  Missing Headers:   ${ansi.yellow(net.missingSecurityHeaders.join(', '))}`);
    }
  }

  // 2.5 Meta-Dispatcher Dynamic Action Surface
  if (report.metaDispatcher?.detected && show('meta')) {
    const md = report.metaDispatcher;
    lines.push('');
    lines.push(ansi.bold('Meta-Dispatcher Dynamic Surface:'));
    lines.push(`  Dispatchers:       ${ansi.cyan(md.dispatcherTools.join(', '))}`);
    lines.push(`  Discovery Tools:   ${ansi.dim(md.discoveryTools.join(', ') || '(none)')}`);
    if (md.expanded) {
      lines.push(`  Modules Granted:   ${md.modules.length > 0 ? md.modules.join(', ') : '(none parsed)'}`);
      lines.push(`  Dynamic Actions:   ${md.actions.length} discovered`);
      for (const act of md.actions.slice(0, 30)) {
        const rTag =
          act.risk === 'exec' || act.risk === 'destructive'
            ? ansi.red(`[${act.risk}]`)
            : act.risk === 'write'
              ? ansi.yellow(`[${act.risk}]`)
              : ansi.green(`[${act.risk}]`);
        lines.push(`    • ${rTag} ${ansi.cyan(act.name)}${act.description ? ` — ${ansi.dim(act.description.slice(0, 90))}` : ''}`);
      }
      if (md.actions.length > 30) {
        lines.push(ansi.dim(`    ... +${md.actions.length - 30} more actions (use --json for full list)`));
      }
      if (md.expansionError) {
        lines.push(ansi.yellow(`  Expansion Note:    ${md.expansionError}`));
      }
    } else if (md.discoveryTools.length > 0) {
      lines.push(ansi.dim('  Tip: run with --expand-meta to enumerate underlying modules & plugin actions live.'));
    }
  }

  // 3. Tool Inventory & Risk Matrix (or Full Grouped Dossier when --detail is enabled)
  if (show('tools') && opts.detail && report.toolsDetail && report.toolsDetail.length > 0) {
    const filterGroup = opts.group?.toLowerCase();
    lines.push('');
    lines.push(
      ansi.bold(
        `Detailed Tool Audit by Risk Group (${report.toolsDetail.length} tools${filterGroup ? `, filter: ${filterGroup}` : ''}):`,
      ),
    );
    for (const grp of RISK_GROUP_ORDER) {
      if (filterGroup && filterGroup !== 'all' && filterGroup !== grp) continue;
      const items = report.toolsDetail.filter((t) => t.risk === grp);
      if (items.length === 0) continue;

      const grpBadge =
        grp === 'exec' || grp === 'destructive'
          ? ansi.red(`[${grp.toUpperCase()} · ${items.length}]`)
          : grp === 'write' || grp === 'network'
            ? ansi.yellow(`[${grp.toUpperCase()} · ${items.length}]`)
            : ansi.green(`[${grp.toUpperCase()} · ${items.length}]`);

      lines.push(`\n  ${ansi.bold(grpBadge)}`);
      for (const t of items) {
        const flagTag = t.findingCount > 0 ? ansi.red(` (${t.findingCount} finding(s))`) : ansi.green(' (clean)');
        lines.push(`    ▸ ${ansi.bold(ansi.cyan(t.name))}${flagTag}  ${ansi.dim(`sha256:${t.hash.slice(0, 12)} · ${t.descriptionChars} chars`)}`);
        if (t.description) {
          lines.push(`      ${ansi.dim(t.description.slice(0, 220))}${t.description.length > 220 ? '...' : ''}`);
        }
        if (t.params.length === 0) {
          lines.push(`      ${ansi.dim('Params: (none)')}`);
        } else {
          lines.push(`      ${ansi.dim('Params:')}`);
          for (const p of t.params) {
            const req = p.required ? ansi.red('*') : '';
            const enumTxt = p.enumValues ? ` [${p.enumValues.join('|')}]` : '';
            lines.push(
              `        - ${p.name}${req} ${ansi.dim(`<${p.type}>${enumTxt} [${p.section}]`)}${p.description ? ` — ${p.description.slice(0, 90)}` : ''}`,
            );
          }
        }
      }
    }
  } else if (show('tools') && report.architecture && report.architecture.toolsByRisk.length > 0) {
    lines.push('');
    lines.push(ansi.bold(`Tool Risk Matrix (${report.architecture.toolCount} tools):`));
    lines.push(
      ansi.dim(`  ${'TOOL'.padEnd(28)} ${'RISK'.padEnd(13)} ${'SHA-256'.padEnd(14)} HINTS`),
    );
    for (const t of report.architecture.toolsByRisk) {
      const riskColored =
        t.risk === 'exec' || t.risk === 'destructive'
          ? ansi.red(t.risk.padEnd(13))
          : t.risk === 'write' || t.risk === 'network'
            ? ansi.yellow(t.risk.padEnd(13))
            : ansi.green(t.risk.padEnd(13));
      const hints: string[] = [];
      if (t.annotations?.readOnlyHint) hints.push('readOnly');
      if (t.annotations?.destructiveHint) hints.push('destructive');
      if (t.annotations?.openWorldHint) hints.push('openWorld');
      lines.push(
        `  ${ansi.cyan(t.name.padEnd(28))} ${riskColored} ${ansi.dim(t.hash.padEnd(14))} ${ansi.dim(hints.join(', ') || '-')}`,
      );
    }
  }

  // 4. Security Findings
  if (show('findings') && report.findings.length > 0) {
    lines.push('');
    lines.push(ansi.bold(`Findings (${report.findings.length}):`));
    for (const f of report.findings) {
      const sev =
        f.severity === 'critical' || f.severity === 'high'
          ? ansi.red(`[${f.severity.toUpperCase()}]`)
          : ansi.yellow(`[${f.severity.toUpperCase()}]`);
      lines.push(`  • ${sev} ${ansi.bold(f.title)} ${ansi.dim(`(${f.engine}/${f.ruleId})`)}`);
      lines.push(`    ${f.detail}`);
      if (f.evidence) lines.push(`    ${ansi.dim(`Evidence: ${f.evidence}`)}`);
      if (f.remediation) lines.push(`    ${ansi.cyan(`Fix: ${f.remediation}`)}`);
    }
  }

  // 5. Architecture & OAuth Endpoints
  if ((show('arch') || show('oauth')) && report.architecture) {
    lines.push('');
    lines.push(ansi.bold(`Architecture (${report.architecture.mode}):`));
    lines.push(`  Transport: ${report.architecture.transport} | Tools: ${report.architecture.toolCount}`);
    if (report.architecture.oauthEndpoints?.length) {
      lines.push(`  OAuth Endpoints:  ${report.architecture.oauthEndpoints.join(' | ')}`);
    }
    if (report.architecture.outboundDomains.length > 0) {
      lines.push(`  Outbound Domains: ${report.architecture.outboundDomains.join(', ')}`);
    }
    if (report.architecture.envVars.length > 0) {
      lines.push(`  Env Vars Read:    ${report.architecture.envVars.join(', ')}`);
    }
    if (report.architecture.osCapabilities.length > 0) {
      lines.push(`  OS Capabilities:  ${report.architecture.osCapabilities.join(', ')}`);
    }
  }

  // 6. Auditor Next Steps
  lines.push('');
  lines.push(
    ansi.dim(
      '  Flags: --detail [--group destructive|read] | --expand-meta | --only tls,meta,poison | --section tls|meta|tools|findings | --verbose | --watch 15',
    ),
  );

  return lines.join('\n');
}

export function formatAuditSuiteTerminal(report: AuditSuiteReport): string {
  const lines: string[] = [];
  lines.push(
    `${ansi.bold(`Audit Suite: ${report.suiteName}`)} (${report.suiteId}) — ${ansi.green(`${report.passed} passed`)}, ${
      report.failed > 0 ? ansi.red(`${report.failed} failed`) : ansi.dim('0 failed')
    } (${report.durationMs}ms)`,
  );
  for (const r of report.results) {
    const icon = r.passed ? ansi.green('✓') : ansi.red('✗');
    lines.push(`  ${icon} ${ansi.bold(r.title)} ${ansi.dim(`[${r.id}]`)}`);
    lines.push(`    ${r.detail}`);
  }
  return lines.join('\n');
}
