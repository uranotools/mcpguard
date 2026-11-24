import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import type {
  CodeEvidenceItem,
  CodeInspectionSummary,
  SecurityEngine,
  SecurityEngineResult,
  SecurityFinding,
  SecurityScanContext,
} from '../../types.js';
import { NATIVE_CONTEXT_KEYS } from '../../core/context.js';

const INSPECTABLE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py']);
const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.venv', '__pycache__']);
const MAX_FILES = 150;
const MAX_FILE_BYTES = 256 * 1024;

const URL_RE = /https?:\/\/[a-zA-Z0-9._-]+(?::\d+)?(?:\/[^\s'"`<>)\]}]+)?/g;
const ENV_JS_RE = /process\.env(?:\.([A-Z0-9_]+)|\[['"]([A-Z0-9_]+)['"]\])/g;
const ENV_PY_RE = /os\.(?:environ(?:\.get)?\(['"]([A-Z0-9_]+)['"]|getenv\(['"]([A-Z0-9_]+)['"])/g;
const SHELL_RE = /\b(child_process|execSync|execFile|spawnSync|os\.system|subprocess\.(?:Popen|run|call))\b/;
const FS_WRITE_RE = /\b(writeFileSync|writeFile|appendFileSync|rmSync|unlinkSync|rmdirSync)\b/;
const EVAL_RE = /\b(eval\s*\(|new\s+Function\s*\()/;

/**
 * Inspects local MCP source code (when available) to extract outbound URLs/domains,
 * accessed environment variables, OS capabilities, and dependencies with file:line evidence.
 */
export function inspectLocalMcpCode(rootPath: string): CodeInspectionSummary {
  const evidence: CodeEvidenceItem[] = [];
  const urlSet = new Set<string>();
  const domainSet = new Set<string>();
  const envSet = new Set<string>();
  const capabilities = new Set<string>();
  let dependencies: Record<string, string> = {};

  const files: string[] = [];
  const stat = statSync(rootPath);
  const baseRoot = stat.isDirectory() ? rootPath : join(rootPath, '..');

  if (stat.isFile()) {
    files.push(rootPath);
  } else {
    walkFiles(rootPath, files);
    const pkgPath = join(rootPath, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as {
          dependencies?: Record<string, string>;
        };
        dependencies = pkg.dependencies ?? {};
      } catch {
        // Ignore malformed package.json
      }
    }
  }

  for (const filePath of files) {
    let content: string;
    try {
      const fstat = statSync(filePath);
      if (fstat.size > MAX_FILE_BYTES) continue;
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const relPath = relative(baseRoot, filePath).replace(/\\/g, '/') || filePath;
    const lines = content.split(/\r?\n/);

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;

      for (const m of lineText.matchAll(URL_RE)) {
        const rawUrl = m[0].replace(/[.,;:'"]+$/, '');
        try {
          const parsed = new URL(rawUrl);
          if (parsed.hostname === 'example.com' || parsed.hostname === 'schemas.org') continue;
          urlSet.add(rawUrl);
          domainSet.add(parsed.hostname);
          evidence.push({ kind: 'outbound-url', value: rawUrl, file: relPath, line: lineNum });
        } catch {
          // Ignore malformed URL literal
        }
      }

      for (const m of lineText.matchAll(ENV_JS_RE)) {
        const key = m[1] ?? m[2];
        if (key) {
          envSet.add(key);
          evidence.push({ kind: 'env-var', value: key, file: relPath, line: lineNum });
        }
      }

      for (const m of lineText.matchAll(ENV_PY_RE)) {
        const key = m[1] ?? m[2];
        if (key) {
          envSet.add(key);
          evidence.push({ kind: 'env-var', value: key, file: relPath, line: lineNum });
        }
      }

      const shellMatch = lineText.match(SHELL_RE);
      if (shellMatch) {
        capabilities.add('shell:exec');
        evidence.push({ kind: 'shell-exec', value: shellMatch[1], file: relPath, line: lineNum });
      }

      const fsMatch = lineText.match(FS_WRITE_RE);
      if (fsMatch) {
        capabilities.add('fs:write');
        evidence.push({ kind: 'fs-write', value: fsMatch[1], file: relPath, line: lineNum });
      }

      const evalMatch = lineText.match(EVAL_RE);
      if (evalMatch) {
        capabilities.add('code:eval');
        evidence.push({ kind: 'dynamic-eval', value: evalMatch[1], file: relPath, line: lineNum });
      }
    });
  }

  if (urlSet.size > 0) capabilities.add('network:outbound');

  return {
    inspectedRoot: rootPath,
    filesScanned: files.length,
    outboundUrls: Array.from(urlSet),
    outboundDomains: Array.from(domainSet),
    envVars: Array.from(envSet),
    capabilities: Array.from(capabilities),
    dependencies,
    evidence,
  };
}

function walkFiles(dir: string, out: string[]): void {
  if (out.length >= MAX_FILES) return;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= MAX_FILES) return;
    if (IGNORED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walkFiles(full, out);
    } else if (INSPECTABLE_EXTS.has(extname(entry).toLowerCase())) {
      out.push(full);
    }
  }
}

export const codeInspectorEngine: SecurityEngine = {
  id: 'code-inspector',
  name: 'Local Code & Outbound URL Inspector',
  async analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult> {
    if (!ctx.localPath || !existsSync(ctx.localPath)) {
      return {
        engineId: 'code-inspector',
        engineName: 'Local Code & Outbound URL Inspector',
        status: 'skip',
        summary:
          ctx.transport === 'stdio'
            ? 'No local source directory resolved for static code inspection'
            : 'Remote black-box MCP (server source code is not observable over HTTP)',
        findings: [],
      };
    }

    const summary = inspectLocalMcpCode(ctx.localPath);
    const findings: SecurityFinding[] = [];

    // Publish directly into ContextStore so ArchitectureReport, SupplyChain, and AuditSuites reuse it!
    ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.CODE_INSPECTION, summary);
    ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.OUTBOUND_URLS, summary.outboundUrls);
    ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.OUTBOUND_DOMAINS, summary.outboundDomains);
    ctx.contextStore?.set(NATIVE_CONTEXT_KEYS.ENV_VARS, summary.envVars);

    if (summary.capabilities.includes('code:eval')) {
      const ev = summary.evidence.find((e) => e.kind === 'dynamic-eval');
      findings.push({
        engine: 'code-inspector',
        ruleId: 'code-dynamic-eval',
        severity: 'high',
        title: 'Dynamic code execution (eval / new Function)',
        detail: `Local MCP source executes dynamic strings at ${ev?.file}:${ev?.line}.`,
        evidence: ev ? `${ev.file}:${ev.line} (${ev.value})` : undefined,
      });
    }

    if (summary.capabilities.includes('shell:exec')) {
      const ev = summary.evidence.find((e) => e.kind === 'shell-exec');
      findings.push({
        engine: 'code-inspector',
        ruleId: 'code-shell-exec',
        severity: 'medium',
        title: 'Subprocess / shell execution primitives in source code',
        detail: `Source uses ${ev?.value ?? 'child_process'} at ${ev?.file}:${ev?.line}.`,
        evidence: ev ? `${ev.file}:${ev.line}` : undefined,
      });
    }

    const sensitiveEnv = summary.envVars.filter((v) =>
      /AWS_SECRET|SSH_|PRIVATE_KEY|NPM_TOKEN|GITHUB_TOKEN|STRIPE_SECRET|DATABASE_URL/i.test(v),
    );
    if (sensitiveEnv.length > 0) {
      findings.push({
        engine: 'code-inspector',
        ruleId: 'code-sensitive-env-read',
        severity: 'medium',
        title: 'Source code reads sensitive environment variables',
        detail: `Reads env vars: ${sensitiveEnv.join(', ')}.`,
      });
    }

    const insecureUrls = summary.outboundUrls.filter(
      (u) => u.startsWith('http://') && !u.includes('127.0.0.1') && !u.includes('localhost'),
    );
    if (insecureUrls.length > 0) {
      findings.push({
        engine: 'code-inspector',
        ruleId: 'code-plaintext-http-egress',
        severity: 'medium',
        title: 'Outbound plaintext HTTP endpoint in source code',
        detail: `Connects over unencrypted HTTP to: ${insecureUrls.slice(0, 3).join(', ')}`,
      });
    }

    const hasHigh = findings.some((f) => f.severity === 'high' || f.severity === 'critical');
    return {
      engineId: 'code-inspector',
      engineName: 'Local Code & Outbound URL Inspector',
      status: hasHigh ? 'fail' : findings.length > 0 ? 'warn' : 'pass',
      summary: `Scanned ${summary.filesScanned} file(s): ${summary.outboundDomains.length} outbound domain(s), ${summary.envVars.length} env var(s), capabilities=[${summary.capabilities.join(', ') || 'none'}]`,
      findings,
      metadata: { codeInspection: summary },
    };
  },
};
