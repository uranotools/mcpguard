# Testing & Audit Suites Guide (`TESTING.md`) — `@uranotools/mcpguard`

`mcpguard` soporta **dos niveles de testing** que comparten el mismo Core SDK:

1. **Tests de unidad e integración del CLI y flags existentes** (`npm test` con `tsx --test test/*.test.ts`).
2. **Grupos de tests de auditoría en vivo (`AuditSuite`)** que ejecutan `mcpguard audit <target> --group <id>` leyendo directamente las variables ya capturadas del MCP en `ContextStore`.

---

## 1. Ejecutar la Suite del Proyecto

```bash
npm run typecheck   # Validación estricta TypeScript (NodeNext)
npm run build       # Compilación a dist/
npm test            # Ejecuta todos los tests en test/*.test.ts
```

### Cobertura de archivos en `test/`

| Archivo | Qué valida |
|---|---|
| `test/schemaForm.test.ts` | Conversión de JSON Schema (objetos anidados, `x-section`, enums, arrays) a `step1..stepN`, coerción y validación. |
| `test/adapters.test.ts` | Adaptadores `stdio`, `http` (JSON + SSE con `notifications/progress`) y `urano-webhook` (firma HMAC). |
| `test/providers.test.ts` | Drivers `openai-compat`, `anthropic` y `gemini` contra servidor SSE mock + `--ai` y `--ai-field`. |
| `test/security.test.ts` | Tool Poisoning, Parameter Smuggling, Unicode oculto, Rug Pull SHA-256 diff, `codeInspector` (URLs/`process.env`/`child_process`), informe Markdown+Mermaid, Cloaking/Split-View, `--probe` Canary, `runtimeGuard` (secretos) y mock de VirusTotal v3. |
| `test/coreExtensibility.test.ts` | `ContextStore` (variables nativas + `publish`/`get`), `FlagAdapter` custom y ejecución de `AuditSuite` compartiendo datos. |
| `test/oauth.test.ts` | Flujo completo OAuth 2.1 + PKCE S256 + RFC 7591 + servidor loopback `127.0.0.1`. |
| `test/cli.test.ts` | Parser de flags, `provider`, `scan`, `report`, `audit`, `doctor`, `--dry-run`, `--json` y políticas `--security strict`. |

---

## 2. Cómo Agregar un Test a un Flag Existente

Para probar un flag nuevo o existente (ej. `--dry-run`, `--ai-field`, `--security strict`), usa `runCli(argv, tempBaseDir)` en un directorio temporal aislado para no tocar `~/.mcpguard`:

```ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../src/cli.js';

test('custom flag test example', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpguard-test-'));
  const code = await runCli(['provider', 'add', 'openrouter', '--api-key', 'sk-test', '--default'], dir);
  assert.equal(code, 0);
});
```

---

## 3. Cómo Crear un Nuevo Grupo de Auditoría (`AuditSuite`)

Puedes crear un grupo de tests reutilizable que lea tanto **variables nativas capturadas del MCP** (`mcp.tools`, `mcp.securityReport`, `mcp.outboundUrls`, `mcp.envVars`) como **datos publicados por otros `FlagAdapter`**:

```ts
import { AuditRunner, createContext, NATIVE_CONTEXT_KEYS } from '@uranotools/mcpguard/core';

const runner = new AuditRunner();
runner.register({
  id: 'my-org-audit',
  name: 'My Org Security Standards',
  description: 'Ensures MCP tools follow naming and HTTPS standards.',
  tests: [
    {
      id: 'no-shell-tools',
      title: 'MCP does not expose shell execution tools',
      severity: 'high',
      async run(ctx) {
        const arch = ctx.get('mcp.architecture');
        const execTools = (arch?.toolsByRisk ?? []).filter((t) => t.risk === 'exec');
        return {
          passed: execTools.length === 0,
          detail: execTools.length === 0 ? 'No exec tools found' : `Found: ${execTools.map((t) => t.name).join(', ')}`,
        };
      },
    },
  ],
});
```

Y para exponerlo en el CLI, expórtalo dentro de un `McpGuardPlugin` (`auditSuites: [...]`) y ejecútalo con:

```bash
mcpguard audit https://mcp.ejemplo.com/v1 --plugin ./my-org-audit.mjs --group my-org-audit --json
```
