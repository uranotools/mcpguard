import type {
  AiProviderAdapter,
  AiSchemaFillRequest,
  AiTextRequest,
} from '../types.js';
import { extractJsonObject } from './openaiCompat.js';

export interface AnthropicProviderOptions {
  id: string;
  name: string;
  baseUrl: string;
  model: string;
  apiKey: string;
}

export class AnthropicProvider implements AiProviderAdapter {
  readonly id: string;
  readonly name: string;
  readonly driver = 'anthropic' as const;
  readonly model: string;

  constructor(private readonly opts: AnthropicProviderOptions) {
    this.id = opts.id;
    this.name = opts.name;
    this.model = opts.model;
  }

  private endpoint(path: string): string {
    return `${this.opts.baseUrl.replace(/\/+$/, '')}${path}`;
  }

  private headers(): Record<string, string> {
    return {
      'content-type': 'application/json',
      'x-api-key': this.opts.apiKey,
      'anthropic-version': '2023-06-01',
    };
  }

  async streamText(req: AiTextRequest, onChunk: (delta: string) => void): Promise<string> {
    const res = await fetch(this.endpoint('/messages'), {
      method: 'POST',
      headers: this.headers(),
      signal: req.signal,
      body: JSON.stringify({
        model: req.model ?? this.model,
        max_tokens: req.maxTokens ?? 1024,
        system: req.systemPrompt,
        stream: true,
        messages: [{ role: 'user', content: req.prompt }],
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Anthropic HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const ct = res.headers.get('content-type') ?? '';
    if (!ct.includes('text/event-stream')) {
      const json = (await res.json()) as { content?: Array<{ text?: string }> };
      const text = json.content?.map((c) => c.text ?? '').join('') ?? '';
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
        try {
          const parsed = JSON.parse(trimmed.slice(5).trim()) as {
            type?: string;
            delta?: { text?: string };
          };
          if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
            full += parsed.delta.text;
            onChunk(parsed.delta.text);
          }
        } catch {
          // Ignore non-delta events
        }
      }
    }
    return full;
  }

  async fillSchema(req: AiSchemaFillRequest): Promise<Record<string, unknown>> {
    const system = [
      'Return ONLY a valid JSON object matching the JSON Schema for this MCP tool.',
      `Tool: ${req.toolName}`,
      req.toolDescription ?? '',
      `Schema:\n${JSON.stringify(req.schema, null, 2)}`,
    ].join('\n\n');

    const res = await fetch(this.endpoint('/messages'), {
      method: 'POST',
      headers: this.headers(),
      signal: req.signal,
      body: JSON.stringify({
        model: req.model ?? this.model,
        max_tokens: 1024,
        system,
        messages: [{ role: 'user', content: req.instruction }],
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Anthropic HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const json = (await res.json()) as { content?: Array<{ text?: string }> };
    const text = json.content?.map((c) => c.text ?? '').join('') ?? '{}';
    return extractJsonObject(text);
  }

  async healthCheck(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
    const start = Date.now();
    try {
      const res = await fetch(this.endpoint('/models'), {
        method: 'GET',
        headers: this.headers(),
      });
      return res.ok
        ? { ok: true, latencyMs: Date.now() - start }
        : { ok: false, latencyMs: Date.now() - start, error: `HTTP ${res.status}` };
    } catch (err) {
      return {
        ok: false,
        latencyMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
