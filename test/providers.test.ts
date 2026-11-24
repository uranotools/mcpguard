import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { AnthropicProvider } from '../src/providers/anthropic.js';
import { GeminiProvider } from '../src/providers/gemini.js';
import { OpenAiCompatProvider } from '../src/providers/openaiCompat.js';
import { fillToolWithAi, streamFieldWithAi } from '../src/providers/aiAssistant.js';
import { buildToolForm } from '../src/core/schemaForm.js';
import { listProviderPresets } from '../src/providers/catalog.js';

test('Provider catalog includes openrouter, huggingface, openai, anthropic, deepseek, alibaba, gemini, ollama', () => {
  const ids = listProviderPresets().map((p) => p.id);
  for (const expected of ['openrouter', 'huggingface', 'openai', 'anthropic', 'deepseek', 'alibaba', 'gemini', 'ollama']) {
    assert.equal(ids.includes(expected), true, `Missing provider preset: ${expected}`);
  }
});

test('OpenAiCompatProvider, AnthropicProvider, and GeminiProvider stream text and fill JSON schemas', async () => {
  const server = createServer((req, res) => {
    const url = req.url ?? '';
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};

      if (url.endsWith('/chat/completions')) {
        if (body.stream) {
          res.writeHead(200, { 'content-type': 'text/event-stream' });
          res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'Café ' } }] })}\n\n`);
          res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'orgánico' } }] })}\n\n`);
          res.write('data: [DONE]\n\n');
          res.end();
        } else {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            choices: [{ message: { content: '{"name":"Café Urano","descripcion":"Tostado artesanal"}' } }],
          }));
        }
        return;
      }

      if (url.endsWith('/messages')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write(`data: ${JSON.stringify({ type: 'content_block_delta', delta: { text: 'Claude ' } })}\n\n`);
        res.write(`data: ${JSON.stringify({ type: 'content_block_delta', delta: { text: 'stream' } })}\n\n`);
        res.end();
        return;
      }

      if (url.includes(':streamGenerateContent')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: 'Gemini ' }] } }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: 'live' }] } }] })}\n\n`);
        res.end();
        return;
      }

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ data: [] }));
    });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

  try {
    const openrouter = new OpenAiCompatProvider({
      id: 'openrouter',
      name: 'OpenRouter',
      baseUrl: base,
      model: 'deepseek/deepseek-chat',
      apiKey: 'sk-test',
    });

    const tool = {
      name: 'register_form',
      description: 'Register product',
      inputSchema: {
        type: 'object',
        required: ['name'],
        properties: { name: { type: 'string' }, descripcion: { type: 'string' } },
      },
    };
    const form = buildToolForm(tool);

    const streamedChunks: string[] = [];
    const fieldVal = await streamFieldWithAi({
      provider: openrouter,
      tool,
      field: form.steps[1],
      instruction: 'Describe el café',
      currentValues: { name: 'Café Urano' },
      onChunk: (d) => streamedChunks.push(d),
    });
    assert.equal(fieldVal, 'Café orgánico');
    assert.deepEqual(streamedChunks, ['Café ', 'orgánico']);

    const filled = await fillToolWithAi({
      provider: openrouter,
      tool,
      instruction: 'Crea un café de prueba',
    });
    assert.equal(filled.name, 'Café Urano');
    assert.equal(filled.descripcion, 'Tostado artesanal');

    const claude = new AnthropicProvider({ id: 'anthropic', name: 'Anthropic', baseUrl: base, model: 'claude-3-5-haiku-latest', apiKey: 'sk-ant' });
    const claudeText = await claude.streamText({ prompt: 'hi' }, () => {});
    assert.equal(claudeText, 'Claude stream');

    const gemini = new GeminiProvider({ id: 'gemini', name: 'Gemini', baseUrl: base, model: 'gemini-2.5-flash', apiKey: 'gem-key' });
    const gemText = await gemini.streamText({ prompt: 'hi' }, () => {});
    assert.equal(gemText, 'Gemini live');
  } finally {
    server.closeAllConnections();
    server.close();
  }
});
