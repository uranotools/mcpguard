import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { HttpTransportAdapter } from '../src/adapters/http.js';
import { StdioTransportAdapter } from '../src/adapters/stdio.js';
import { UranoWebhookAdapter } from '../src/adapters/uranoWebhook.js';
import { McpConnector } from '../src/core/connector.js';
import { createContext, NATIVE_CONTEXT_KEYS } from '../src/core/context.js';
import type { McpProgressEvent } from '../src/types.js';

test('HttpTransportAdapter handles SSE notifications/progress and returns final tool result', async () => {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
        id?: number;
        method: string;
        params?: Record<string, unknown>;
      };

      if (body.method === 'initialize') {
        res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'sess-1' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2025-03-26', serverInfo: { name: 'mock-http-mcp', version: '1.0.0' } } }));
        return;
      }
      if (body.method === 'tools/list') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            tools: [{ name: 'build_report', description: 'Generate report', inputSchema: { type: 'object', properties: { title: { type: 'string' } } } }],
          },
        }));
        return;
      }
      if (body.method === 'tools/call') {
        const token = (body.params?._meta as { progressToken?: string } | undefined)?.progressToken ?? 't1';
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: token, progress: 50, total: 100, message: 'Halfway' } })}\n\n`);
        res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: token, progress: 100, total: 100, message: 'Done' } })}\n\n`);
        res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: 'Report ready!' }] } })}\n\n`);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: {} }));
    });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  const ctx = createContext();
  const connector = new McpConnector(new HttpTransportAdapter({ url: `http://127.0.0.1:${port}/mcp` }), ctx);

  try {
    const disc = await connector.discover();
    assert.equal(disc.serverInfo.name, 'mock-http-mcp');
    assert.equal(disc.tools.length, 1);
    assert.equal(ctx.get(NATIVE_CONTEXT_KEYS.TOOLS), disc.tools);

    const progressEvents: McpProgressEvent[] = [];
    const result = await connector.callTool('build_report', { title: 'Q4' }, {
      onProgress: (ev) => progressEvents.push(ev),
    });

    assert.equal(progressEvents.length, 2);
    assert.equal(progressEvents[0].progress, 50);
    assert.equal(progressEvents[1].progress, 100);
    assert.equal(result.content[0].text, 'Report ready!');
  } finally {
    await connector.disconnect();
    server.closeAllConnections();
    server.close();
  }
});

test('StdioTransportAdapter communicates with a local JSON-RPC MCP child process', async () => {
  const mockServerScript = `
    const rl = require('readline').createInterface({ input: process.stdin });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      const msg = JSON.parse(line);
      if (msg.method === 'initialize') {
        console.log(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { serverInfo: { name: 'stdio-mock' } } }));
      } else if (msg.method === 'tools/list') {
        console.log(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'ping', description: 'Ping tool' }] } }));
      } else if (msg.method === 'tools/call') {
        console.log(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'pong' }] } }));
      } else if (msg.id) {
        console.log(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }));
      }
    });
  `;

  const adapter = new StdioTransportAdapter({
    command: process.execPath,
    args: ['-e', mockServerScript],
  });
  const connector = new McpConnector(adapter);
  try {
    const disc = await connector.discover();
    assert.equal(disc.serverInfo.name, 'stdio-mock');
    assert.equal(disc.tools[0].name, 'ping');
    const res = await connector.callTool('ping', {});
    assert.equal(res.content[0].text, 'pong');
  } finally {
    await connector.disconnect();
  }
});

test('UranoWebhookAdapter signs requests with HMAC x-urano-signature', async () => {
  const secret = 'test-hmac-secret';
  let receivedSig = '';
  let receivedBody = '';

  const server = createServer((req, res) => {
    receivedSig = String(req.headers['x-urano-signature'] ?? '');
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      receivedBody = Buffer.concat(chunks).toString('utf8');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, reply: 'Hello from Urano' }));
    });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  const connector = new McpConnector(new UranoWebhookAdapter({ url: `http://127.0.0.1:${port}/webhook`, secret }));

  try {
    const disc = await connector.discover();
    assert.equal(disc.tools.some((t) => t.name === 'chat'), true);
    const res = await connector.callTool('chat', { text: 'Hola agente' });
    const expectedSig = createHmac('sha256', secret).update(receivedBody).digest('hex');
    assert.equal(receivedSig, expectedSig);
    assert.match(res.content[0].text ?? '', /Hello from Urano/);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});
