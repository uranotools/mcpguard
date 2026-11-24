# `@uranotools/mcpguard` (`mcpguard`)

**Interactive MCP CLI/TUI + Inline AI Flag Assistant + VirusTotal-style MCP Security Shield.**

Convierte cualquier servidor **Model Context Protocol (MCP)** — local (`stdio`), remoto (`Streamable HTTP / SSE` con OAuth en navegador) o webhooks HMAC de Urano — en un CLI interactivo guiado por secciones, con progreso visual real, rellenado asistido por IA y auditoría de ciberseguridad multi-motor.

---

## Características Principales

- **Formularios interactivos por secciones (`step1`, `step2`…):** Autogenerados desde `tools/list` (`inputSchema`), con soporte dual para scripting (`--flag valor --json`) y wizard interactivo (`-i`).
- **Progreso visual real:** Consume `notifications/progress` y `notifications/message` nativos de MCP.
- **IA en tiempo real en cualquier flag:** Usa `--ai "<prompt>"` para rellenar todo el formulario, `--ai-field campo="<prompt>"` o escribe `@ai <prompt>` dentro de cualquier paso del wizard con streaming en vivo.
- **Catálogo de proveedores IA incluido:** `openrouter`, `huggingface`, `openai`, `anthropic`, `deepseek`, `alibaba`, `gemini`, `ollama` y endpoints custom OpenAI-compatible.
- **`install <url>` con OAuth 2.1 + PKCE en navegador:** Detecta `401` / `.well-known/oauth-authorization-server`, levanta callback local en `127.0.0.1` y abre tu navegador automáticamente.
- **Capa de Ciberseguridad "VirusTotal para MCP" (`scan` / `report` / `audit`):**
  - **Tool Poisoning & Parameter Smuggling:** prompt injection, caracteres Unicode invisibles/BiDi, Base64 oculto, *padding evasion*, campos trampa (`sidenote`, `conversation_history`, etc.) y puente opcional con `@uranotools/urano-guard`.
  - **Protección contra Rug Pulls (`trust.lock.json`):** fija el hash SHA-256 de cada tool al instalar y detecta cambios silenciosos antes de ejecutar.
  - **Auditoría externa por URL:** postura HTTP/TLS/CORS/OAuth, detección de **Cloaking / Split-View** y sondeo seguro opt-in (`--probe`) con *Canary Tokens* y detección de fugas en errores.
  - **Inspección profunda local + Informe de Arquitectura:** en MCPs locales extrae URLs/dominios salientes, `process.env` leídas y capacidades OS (`archivo:línea`) y genera diagramas Mermaid (`mcpguard report`).

---

## Instalación

```bash
npm install -g @uranotools/mcpguard
# o uso directo con npx
npx @uranotools/mcpguard --help
```

Requisitos: **Node.js >= 18.0.0**.

---

## Inicio Rápido

### 1. Configurar un proveedor de IA

```bash
# Presets incluidos: openrouter, huggingface, openai, anthropic, deepseek, alibaba, gemini, ollama
mcpguard provider add openrouter --api-key sk-or-... --model anthropic/claude-3.5-sonnet --default
mcpguard provider add deepseek --api-key sk-...
mcpguard provider add alibaba --api-key sk-... --model qwen-plus
mcpguard provider add huggingface --api-key hf_...
mcpguard provider list
mcpguard provider test
```

### 2. Escanear e instalar un MCP (URL con OAuth o local `stdio`)

```bash
# Escaneo estilo VirusTotal antes de instalar
mcpguard scan https://mcp.ejemplo.com/v1 --probe --deep

# Generar informe completo con diagrama de arquitectura Mermaid
mcpguard report ./mi-mcp-local --format md --out audit.md

# Instalar MCP remoto (si requiere login, abre el navegador automáticamente vía OAuth 2.1 + PKCE)
mcpguard install https://mcp.ejemplo.com/v1 --name ejemplo

# Instalar MCP local (stdio)
mcpguard install "npx -y @modelcontextprotocol/server-filesystem ./docs" --name fs
```

### 3. Ejecutar acciones, wizard por pasos y flags con IA

```bash
# Listar todas las acciones del MCP
mcpguard ejemplo list

# Wizard interactivo paso a paso (escribe "@ai <prompt>" en cualquier campo para streaming en vivo)
mcpguard ejemplo register_form -i

# Flags directos (apto para scripts y CI/CD)
mcpguard ejemplo register_form --name "Café Urano" --descripcion "Tostado de especialidad" --json

# Streaming IA en un solo flag
mcpguard ejemplo register_form --name "Café Urano" --ai-field descripcion="Redacta una descripción breve"

# Rellenado completo con IA + preview (dry-run)
mcpguard ejemplo register_form --ai "Registra un café orgánico de Chiapas" --dry-run
```

### 4. Auditorías, Trust Lock y utilidades nativas

```bash
mcpguard audit ejemplo --group owasp-mcp   # Corre grupos de tests de auditoría
mcpguard trust diff ejemplo                # Revisa si alguna tool cambió (Rug Pull)
mcpguard trust approve ejemplo             # Actualiza hashes tras validar el diff
mcpguard inspect ejemplo register_form     # Muestra schema y pasos step1..stepN
mcpguard doctor                            # Diagnóstico del entorno
mcpguard export --target claude            # Exporta configuración a mcp.json
```

---

## Documentación Open Source

- **Usuarios:** este archivo (`README.md`)
- **Desarrolladores y extensibilidad (Adaptadores, `FlagAdapter`, Core SDK):** [DEV_README.md](./DEV_README.md)
- **Testing y grupos de auditoría (`AuditSuite`):** [TESTING.md](./TESTING.md)

MIT © Urano Open Source
