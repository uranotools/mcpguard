import type {
  AiProviderAdapter,
  AiSchemaFillRequest,
  AiTextRequest,
} from '../types.js';
import { extractJsonObject } from './openaiCompat.js';

export interface GeminiProviderOptions {
  id: string;
  name: string;
  baseUrl: string;
  model: string;
  apiKey: string;
}

export class GeminiProvider implements AiProviderAdapter {
  readonly id: string;
  readonly name: string;
  readonly driver = 'gemini' as const;
  readonly model: string;

  constructor(private readonly opts: GeminiProviderOptions) {
    this.id = opts.id;
    this.name = opts.name;
    this.model = opts.model;
  }

  private endpoint(path: string): string {
    return `${this.opts.baseUrl.replace(/\/+$/, '')}${path}`;
  }

  async streamText(req: AiTextRequest, onChunk: (delta: string) => void): Promise<string> {
    const model = req.model ?? this.model;
    const url = `${this.endpoint(`/models/${model}:streamGenerateContent`)}?alt=sse&key=${encodeURIComponent(this.opts.apiKey)}`;

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: req.signal,
      body: JSON.stringify({
        systemInstruction: req.systemPrompt ? { parts: [{ text: req.systemPrompt }] } : undefined,
        contents: [{ role: 'user', parts: [{ text: req.prompt }] }],
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Gemini HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const ct = res.headers.get('content-type') ?? '';
    if (!ct.includes('text/event-stream')) {
      const json = (await res.json()) as {
        candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      };
      const text = json.candidates?.[0]?.content?.parts?.map((p) => p.text ?? '').join('') ?? '';
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
            candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
          };
          const delta = parsed.candidates?.[0]?.content?.parts?.map((p) => p.text ?? '').join('');
          if (delta) {
            full += delta;
            onChunk(delta);
          }
        } catch {
          // Ignore malformed line
        }
      }
    }
    return full;
  }

  async fillSchema(req: AiSchemaFillRequest): Promise<Record<string, unknown>> {
    const model = req.model ?? this.model;
    const url = `${this.endpoint(`/models/${model}:generateContent`)}?key=${encodeURIComponent(this.opts.apiKey)}`;
    const systemPrompt = [
      'Return ONLY a valid JSON object matching the JSON Schema for this MCP tool.',
      `Tool: ${req.toolName}`,
      req.toolDescription ?? '',
      `Schema:\n${JSON.stringify(req.schema, null, 2)}`,
    ].join('\n\n');

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: req.signal,
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: req.instruction }] }],
        generationConfig: { responseMimeType: 'application/json' },
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Gemini HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const json = (await res.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    const text = json.candidates?.[0]?.content?.parts?.map((p) => p.text ?? '').join('') ?? '{}';
    return extractJsonObject(text);
  }

  async healthCheck(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
    const start = Date.now();
    try {
      const url = `${this.endpoint('/models')}?key=${encodeURIComponent(this.opts.apiKey)}`;
      const res = await fetch(url, { method: 'GET' });
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
