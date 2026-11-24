# Developer Guide (`DEV_README.md`) — `@uranotools/mcpguard`

Esta guía explica la arquitectura interna normalizada de `mcpguard` y cómo extenderlo creando **adaptadores de transporte**, **adaptadores de flags (`FlagAdapter`)**, **motores de seguridad (`SecurityEngine`)** y **grupos de auditoría (`AuditSuite`)** reutilizando la librería Core interna.

---

## 1. Arquitectura de Ciclo Único y Autoalimentado

`mcpguard` evita repetir handshakes y llamadas `tools/list`. Todo fluye a través de `McpGuardPipeline` + `ContextStore` (`@uranotools/mcpguard/core`):

```text
[CLI Flags] -> Connect (1x) -> Discover -> ContextStore (ctx)
                                              │
                 ┌────────────────────────────┼────────────────────────────┐
                 ▼                            ▼                            ▼
         Security Engines               FlagAdapters                  AuditSuites
     (leen ctx, publican report)   (leen ctx, publican datos)     (leen todo de ctx)
```

### Variables Nativas Expuestas en `ContextStore`

Importa `NATIVE_CONTEXT_KEYS` desde `@uranotools/mcpguard/core`:

| Key | Tipo | Descripción |
|---|---|---|
| `mcp.target` | `string` | URL o comando del servidor MCP |
| `mcp.serverName` | `string` | Alias del servidor |
| `mcp.transport` | `TransportKind` | `stdio` \| `http` \| `sse` \| `urano-webhook` |
| `mcp.serverInfo` | `McpServerInfo` | Nombre, versión y capabilities de `initialize` |
| `mcp.tools` | `McpToolDefinition[]` | Herramientas descubiertas en `tools/list` |
| `mcp.resources` | `McpResourceDefinition[]` | Recursos descubiertos |
| `mcp.prompts` | `McpPromptDefinition[]` | Prompts descubiertos |
| `mcp.toolHashes` | `Record<string, string>` | Hashes SHA-256 canónicos por tool |
| `mcp.securityReport` | `SecurityReport` | Veredicto completo estilo VirusTotal |
| `mcp.architecture` | `ArchitectureSummary` | Resumen de arquitectura inferida |
| `mcp.codeInspection` | `CodeInspectionSummary` | Evidencia `archivo:línea` en MCPs locales |
| `mcp.outboundUrls` | `string[]` | URLs salientes detectadas en código local |
| `mcp.outboundDomains` | `string[]` | Dominios salientes detectados |
| `mcp.envVars` | `string[]` | Variables de entorno leídas en código local |
| `invocation.toolName` | `string` | Tool ejecutada |
| `invocation.args` | `Record<string, unknown>` | Argumentos enviados |
| `invocation.result` | `McpToolCallResult` | Resultado retornado por el MCP |

---

## 2. Subpath Exports (Librería Core Interna)

Puedes importar módulos específicos sin cargar todo el CLI:

```ts
import { createContext, NATIVE_CONTEXT_KEYS, FlagRegistry, AuditRunner } from '@uranotools/mcpguard/core';
import { StdioTransportAdapter, HttpTransportAdapter } from '@uranotools/mcpguard/adapters';
import { runSecurityScan, inspectLocalMcpCode } from '@uranotools/mcpguard/security';
import { createAiProviderAdapter, PROVIDER_CATALOG } from '@uranotools/mcpguard/providers';
import { runOAuthBrowserLogin } from '@uranotools/mcpguard/auth';
```

---

## 3. Cómo Crear un Adaptador de Flag (`FlagAdapter`) + Publicar Datos

Un `FlagAdapter` te permite añadir un nuevo flag al CLI, leer datos ya capturados del MCP y **publicar nuevos datos** en `ctx` para que otros adaptadores o tests los consuman.

```ts
// my-compliance-plugin.mjs
import { NATIVE_CONTEXT_KEYS } from '@uranotools/mcpguard/core';

/** @type {import('@uranotools/mcpguard').McpGuardPlugin} */
export default {
  name: 'compliance-plugin',
  version: '1.0.0',
  flags: [
    {
      flag: 'compliance-tag',
      description: 'Computes compliance metadata from already-captured MCP tools and exposes it to audit suites.',
      valueType: 'string',
      phase: 'post-scan',
      async run(tag, ctx) {
        const tools = ctx.get(NATIVE_CONTEXT_KEYS.TOOLS) ?? [];
        const report = ctx.get(NATIVE_CONTEXT_KEYS.SECURITY_REPORT);

        // Exponer información propia para que otros adaptadores o tests la lean
        ctx.publish('compliance.summary', {
          tag,
          toolCount: tools.length,
          verdict: report?.verdict ?? 'UNKNOWN',
          approved: (report?.score ?? 0) >= 80,
        }, 'compliance-plugin');
      },
      // Opcional: grupo de tests asociado directamente a este flag
      auditSuite: {
        id: 'compliance',
        name: 'Compliance Gate Suite',
        description: 'Validates compliance.summary published by --compliance-tag',
        tests: [
          {
            id: 'compliance-score-min',
            title: 'MCP meets compliance score threshold (>=80)',
            severity: 'high',
            async run(ctx) {
              const summary = ctx.get('compliance.summary');
              return {
                passed: Boolean(summary?.approved),
                detail: `Tag=${summary?.tag ?? 'none'}, verdict=${summary?.verdict ?? 'N/A'}`,
              };
            },
          },
        ],
      },
    },
  ],
};
```

Ejecútalo directamente desde el CLI sin tocar el código fuente de `mcpguard`:

```bash
mcpguard audit ./mi-mcp --plugin ./my-compliance-plugin.mjs --compliance-tag soc2 --group compliance
```

---

## 4. Cómo Crear un Nuevo Motor de Seguridad (`SecurityEngine`)

Implementa `SecurityEngine` y regístralo en `plugin.securityEngines` o pásalo a `runSecurityScan(ctx, { extraEngines: [miMotor] })`:

```ts
import type { SecurityEngine } from '@uranotools/mcpguard';

export const customDomainPolicyEngine: SecurityEngine = {
  id: 'corp-domain-policy',
  name: 'Corporate Domain Allowlist',
  async analyze(ctx) {
    const domains = ctx.contextStore?.get<string[]>('mcp.outboundDomains') ?? [];
    const forbidden = domains.filter((d) => d.endsWith('.untrusted.example'));
    return {
      engineId: 'corp-domain-policy',
      engineName: 'Corporate Domain Allowlist',
      status: forbidden.length > 0 ? 'fail' : 'pass',
      summary: forbidden.length > 0 ? `Blocked domains: ${forbidden.join(', ')}` : 'All domains allowed',
      findings: forbidden.map((d) => ({
        engine: 'corp-domain-policy',
        ruleId: 'corp-forbidden-domain',
        severity: 'high',
        title: `Forbidden outbound domain: ${d}`,
        detail: `Domain ${d} is blocked by corporate policy.`,
      })),
    };
  },
};
```

---

## 5. Cómo Crear un Adaptador de Transporte (`McpTransportAdapter`)

Implementa los 4 métodos normalizados (`connect`, `disconnect`, `request`, `onNotification`) definidos en `src/types.ts` y regístralo en `src/adapters/index.ts`.
