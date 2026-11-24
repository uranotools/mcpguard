import type {
  AiProviderAdapter,
  AiSchemaFillRequest,
  AiTextRequest,
} from '../types.js';

export interface OpenAiCompatOptions {
  id: string;
  name: string;
  baseUrl: string;
  model: string;
  apiKey?: string;
  extraHeaders?: Record<string, string>;
}

/**
 * Unified OpenAI-compatible driver powering OpenAI, OpenRouter, Hugging Face,
 * DeepSeek, Alibaba DashScope (Qwen), Ollama, and custom endpoints.
 */
export class OpenAiCompatProvider implements AiProviderAdapter {
  readonly id: string;
  readonly name: string;
  readonly driver = 'openai-compat' as const;
  readonly model: string;

  constructor(private readonly opts: OpenAiCompatOptions) {
    this.id = opts.id;
    this.name = opts.name;
    this.model = opts.model;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      'content-type': 'application/json',
      ...this.opts.extraHeaders,
    };
    if (this.opts.apiKey) {
      h.authorization = `Bearer ${this.opts.apiKey}`;
    }
    return h;
  }

  private endpoint(path: string): string {
    return `${this.opts.baseUrl.replace(/\/+$/, '')}${path}`;
  }

  async streamText(req: AiTextRequest, onChunk: (delta: string) => void): Promise<string> {
    const messages: Array<{ role: string; content: string }> = [];
    if (req.systemPrompt) messages.push({ role: 'system', content: req.systemPrompt });
    messages.push({ role: 'user', content: req.prompt });

    const res = await fetch(this.endpoint('/chat/completions'), {
      method: 'POST',
      headers: this.headers(),
      signal: req.signal,
      body: JSON.stringify({
        model: req.model ?? this.model,
        messages,
        stream: true,
        temperature: req.temperature ?? 0.4,
        max_tokens: req.maxTokens ?? 1024,
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Provider "${this.id}" HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const ct = res.headers.get('content-type') ?? '';
    if (!ct.includes('text/event-stream')) {
      const json = (await res.json()) as {
        choices?: Array<{ message?: { content?: string } }>;
      };
      const text = json.choices?.[0]?.message?.content ?? '';
      if (text) onChunk(text);
      return text;
    }

    const reader = res.body?.getReader();
    if (!reader) return '';
    const decoder = new TextDecoder();
    let buffer = '';
    let full = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) continue;
        const data = trimmed.slice(5).trim();
        if (data === '[DONE]') continue;
        try {
          const parsed = JSON.parse(data) as {
            choices?: Array<{ delta?: { content?: string } }>;
          };
          const delta = parsed.choices?.[0]?.delta?.content;
          if (delta) {
            full += delta;
            onChunk(delta);
          }
        } catch {
          // Ignore malformed chunk
        }
      }
    }
    return full;
  }

  async fillSchema(req: AiSchemaFillRequest): Promise<Record<string, unknown>> {
    const systemPrompt = [
      'You are an assistant filling structured JSON arguments for an MCP tool.',
      'Return ONLY a valid JSON object matching the provided JSON Schema. Do not wrap in markdown fences.',
      `Tool: ${req.toolName}`,
      req.toolDescription ? `Description: ${req.toolDescription}` : '',
      `JSON Schema:\n${JSON.stringify(req.schema, null, 2)}`,
      req.existingValues && Object.keys(req.existingValues).length > 0
        ? `Keep these already provided values unless explicitly overridden:\n${JSON.stringify(req.existingValues, null, 2)}`
        : '',
    ]
      .filter(Boolean)
      .join('\n\n');

    const res = await fetch(this.endpoint('/chat/completions'), {
      method: 'POST',
      headers: this.headers(),
      signal: req.signal,
      body: JSON.stringify({
        model: req.model ?? this.model,
        temperature: 0.2,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: req.instruction },
        ],
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Provider "${this.id}" HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const json = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const raw = json.choices?.[0]?.message?.content ?? '{}';
    return extractJsonObject(raw);
  }

  async healthCheck(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
    const start = Date.now();
    try {
      const res = await fetch(this.endpoint('/models'), {
        method: 'GET',
        headers: this.headers(),
      });
      if (!res.ok) {
        return { ok: false, latencyMs: Date.now() - start, error: `HTTP ${res.status}` };
      }
      return { ok: true, latencyMs: Date.now() - start };
    } catch (err) {
      return {
        ok: false,
        latencyMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}

export function extractJsonObject(raw: string): Record<string, unknown> {
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
  const first = cleaned.indexOf('{');
  const last = cleaned.lastIndexOf('}');
  const slice = first >= 0 && last > first ? cleaned.slice(first, last + 1) : cleaned;
  const parsed = JSON.parse(slice);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Model did not return a JSON object');
  }
  return parsed as Record<string, unknown>;
}
