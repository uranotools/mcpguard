import type {
  McpToolDefinition,
  MetaDispatcherSummary,
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';
import { classifyToolRisk } from './blastRadius.js';

const DISPATCHER_NAME_RE = /\b(call_action|run_action|invoke_action|execute_action|dispatch|call_tool|invoke_tool|run_plugin|exec_action)\b/i;
const DISCOVERY_NAME_RE = /\b(list_modules|list_actions|list_plugins|list_capabilities|list_operations|get_actions|discover_actions)\b/i;

function isMetaDispatcherTool(tool: McpToolDefinition): boolean {
  if (DISPATCHER_NAME_RE.test(tool.name)) return true;
  const propNames = Object.keys(tool.inputSchema?.properties ?? {}).map((k) => k.toLowerCase());
  const hasActionSelector = propNames.some((p) => ['action', 'operation', 'method', 'tool', 'command'].includes(p));
  const hasDynamicPayload = propNames.some((p) => ['params', 'arguments', 'args', 'payload', 'input', 'body'].includes(p));
  return hasActionSelector && hasDynamicPayload;
}

function isMetaDiscoveryTool(tool: McpToolDefinition): boolean {
  if (!DISCOVERY_NAME_RE.test(tool.name)) return false;
  const risk = classifyToolRisk(tool);
  return risk === 'read' && tool.annotations?.destructiveHint !== true;
}

/**
 * Meta-Dispatcher & Dynamic Action Surface Engine:
 * 1. Detects MCP gateways that multiplex many backend actions behind a single dispatcher tool
 *    (e.g. list_modules + list_actions + call_action).
 * 2. When --expand-meta is enabled, safely invokes ONLY read-only discovery tools to inspect
 *    the underlying modules, plugins, and dynamic actions in real time.
 */
export const metaDispatcherEngine: SecurityEngine = {
  id: 'meta-dispatcher',
  name: 'Meta-Dispatcher & Dynamic Surface',
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    const dispatchers = ctx.tools.filter(isMetaDispatcherTool);
    const discoveryTools = ctx.tools.filter(isMetaDiscoveryTool);

    if (dispatchers.length === 0) {
      return {
        engineId: 'meta-dispatcher',
        engineName: 'Meta-Dispatcher & Dynamic Surface',
        status: 'pass',
        summary: 'Direct static tool surface (no meta-dispatcher gateway detected)',
        findings: [],
      };
    }

    const findings: SecurityFinding[] = [];
    const summary: MetaDispatcherSummary = {
      detected: true,
      dispatcherTools: dispatchers.map((t) => t.name),
      discoveryTools: discoveryTools.map((t) => t.name),
      expanded: false,
      modules: [],
      actions: [],
    };

    findings.push({
      engine: 'meta-dispatcher',
      ruleId: 'meta-dispatcher-surface',
      severity: 'info',
      title: `Dynamic Meta-Dispatcher gateway detected (${dispatchers.map((t) => t.name).join(', ')})`,
      detail:
        'This MCP multiplexes dynamic backend actions behind a dispatcher tool. Static tools/list alone does not show all underlying plugin actions.',
      target: `tool:${dispatchers[0].name}`,
      remediation:
        discoveryTools.length > 0
          ? 'Run with --expand-meta to safely enumerate underlying modules and actions via read-only discovery tools.'
          : 'Audit backend plugin permissions and enforce least-privilege scopes.',
    });

    // Optional live expansion using ONLY read-only discovery tools (never mutating tools!)
    if (ctx.expandMeta && ctx.connector && discoveryTools.length > 0) {
      summary.expanded = true;
      const seenModules = new Set<string>();
      const seenActions = new Map<string, { name: string; module?: string; plugin?: string; risk: string; description?: string }>();

      for (const discTool of discoveryTools) {
        try {
          const res = await ctx.connector.callTool(discTool.name, {});
          const rawText = res.content.map((c) => c.text ?? '').join('\n').trim();
          if (!rawText) continue;

          extractModulesAndActions(rawText, seenModules, seenActions);
        } catch (err) {
          summary.expansionError = err instanceof Error ? err.message : String(err);
        }
      }

      summary.modules = Array.from(seenModules);
      summary.actions = Array.from(seenActions.values());

      // Flag high-risk underlying actions discovered dynamically
      const highRiskActions = summary.actions.filter(
        (a) => a.risk === 'exec' || a.risk === 'destructive',
      );
      if (highRiskActions.length > 0) {
        findings.push({
          engine: 'meta-dispatcher',
          ruleId: 'meta-dynamic-high-risk-actions',
          severity: 'medium',
          title: `${highRiskActions.length} high-risk underlying action(s) exposed behind meta-dispatcher`,
          detail: `Dynamic actions with destructive/exec risk: ${highRiskActions.slice(0, 8).map((a) => a.name).join(', ')}`,
          target: `tool:${dispatchers[0].name}`,
        });
      }
    }

    const hasWarn = findings.some((f) => f.severity === 'medium' || f.severity === 'high' || f.severity === 'critical');
    const descParts = [`dispatchers=[${summary.dispatcherTools.join(', ')}]`];
    if (summary.expanded) {
      descParts.push(`expanded: ${summary.modules.length} module(s), ${summary.actions.length} action(s)`);
    } else if (discoveryTools.length > 0) {
      descParts.push(`pass --expand-meta to inspect via [${discoveryTools.map((t) => t.name).join(', ')}]`);
    }

    return {
      engineId: 'meta-dispatcher',
      engineName: 'Meta-Dispatcher & Dynamic Surface',
      status: hasWarn ? 'warn' : 'pass',
      summary: descParts.join(' · '),
      findings,
      metadata: { metaDispatcher: summary },
    };
  },
};

function extractModulesAndActions(
  rawText: string,
  modules: Set<string>,
  actions: Map<string, { name: string; module?: string; plugin?: string; risk: string; description?: string }>,
): void {
  try {
    const parsed = JSON.parse(rawText) as unknown;
    walkJsonForSurface(parsed, modules, actions);
    return;
  } catch {
    // Fallback: extract structured bullets / lines if server returned plain text/markdown
    for (const line of rawText.split(/\r?\n/)) {
      const m = line.match(/^\s*[-*•]\s*`?([a-zA-Z0-9_.:/-]+)`?(?:\s*[-–:]\s*(.+))?$/);
      if (!m) continue;
      const name = m[1];
      const desc = m[2]?.trim();
      const risk = classifyToolRisk({ name, description: desc });
      if (!actions.has(name)) {
        actions.set(name, { name, risk, description: desc });
      }
    }
  }
}

function walkJsonForSurface(
  node: unknown,
  modules: Set<string>,
  actions: Map<string, { name: string; module?: string; plugin?: string; risk: string; description?: string }>,
  currentModule?: string,
  currentPlugin?: string,
): void {
  if (!node) return;
  if (Array.isArray(node)) {
    for (const item of node) {
      if (typeof item === 'string') {
        if (currentModule || currentPlugin) {
          const fullName = currentPlugin ? `${currentPlugin}.${item}` : item;
          actions.set(fullName, {
            name: fullName,
            module: currentModule,
            plugin: currentPlugin,
            risk: classifyToolRisk({ name: item }),
          });
        } else {
          modules.add(item);
        }
      } else {
        walkJsonForSurface(item, modules, actions, currentModule, currentPlugin);
      }
    }
    return;
  }

  if (typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    const modName =
      typeof obj.module === 'string'
        ? obj.module
        : typeof obj.moduleId === 'string'
          ? obj.moduleId
          : currentModule;
    const plugName =
      typeof obj.plugin === 'string'
        ? obj.plugin
        : typeof obj.pluginId === 'string'
          ? obj.pluginId
          : currentPlugin;

    if (modName) modules.add(modName);

    // If this object itself looks like an action descriptor
    const actName =
      typeof obj.action === 'string'
        ? obj.action
        : typeof obj.name === 'string' && (obj.plugin || obj.method || obj.access || obj.params || obj.parameters || obj.description)
          ? obj.name
          : undefined;

    if (actName && !Array.isArray(obj.plugins) && !Array.isArray(obj.actions)) {
      const desc = typeof obj.description === 'string' ? obj.description : undefined;
      const key = plugName ? `${plugName}.${actName}` : modName ? `${modName}.${actName}` : actName;
      actions.set(key, {
        name: key,
        module: modName,
        plugin: plugName,
        risk: classifyToolRisk({
          name: actName,
          description: desc,
          annotations:
            obj.access === 'write'
              ? { destructiveHint: /delete|remove|drop|revoke/i.test(actName) }
              : undefined,
        }),
        description: desc,
      });
    }

    if (Array.isArray(obj.modules)) {
      walkJsonForSurface(obj.modules, modules, actions, modName, plugName);
    }
    if (Array.isArray(obj.plugins)) {
      for (const p of obj.plugins) {
        const pObj = p && typeof p === 'object' ? (p as Record<string, unknown>) : null;
        const pName = typeof pObj?.name === 'string' ? pObj.name : typeof pObj?.id === 'string' ? pObj.id : plugName;
        walkJsonForSurface(p, modules, actions, modName, pName);
      }
    }
    if (Array.isArray(obj.actions)) {
      walkJsonForSurface(obj.actions, modules, actions, modName, plugName);
    }
    if (obj.data && typeof obj.data === 'object') {
      walkJsonForSurface(obj.data, modules, actions, modName, plugName);
    }
  }
}
