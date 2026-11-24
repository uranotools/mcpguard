import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { parseResourceMetadataUrl, runOAuthBrowserLogin } from '../src/auth/oauth.js';

test('parseResourceMetadataUrl extracts RFC 9728 URL from WWW-Authenticate header', () => {
  const url = parseResourceMetadataUrl(
    'Bearer realm="mcp", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/ads"',
  );
  assert.equal(url, 'https://mcp.example.com/.well-known/oauth-protected-resource/ads');
});

test('runOAuthBrowserLogin executes OAuth 2.1 discovery, dynamic registration, PKCE S256, and loopback callback', async () => {
  let expectedChallenge = '';
  let capturedRedirectUri = '';

  const authServer = createServer((req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1');

    if (reqUrl.pathname === '/.well-known/oauth-authorization-server') {
      const origin = `http://${req.headers.host}`;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        registration_endpoint: `${origin}/register`,
        code_challenge_methods_supported: ['S256'],
      }));
      return;
    }

    if (reqUrl.pathname === '/register') {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ client_id: 'dyn-client-123' }));
      return;
    }

    if (reqUrl.pathname === '/token') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        const verifier = form.get('code_verifier') ?? '';
        const computed = createHash('sha256')
          .update(verifier)
          .digest('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/g, '');

        if (computed !== expectedChallenge) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ access_token: 'oauth-access-token-xyz', token_type: 'Bearer', expires_in: 3600 }));
      });
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((r) => authServer.listen(0, '127.0.0.1', () => r()));
  const port = (authServer.address() as { port: number }).port;

  try {
    const result = await runOAuthBrowserLogin({
      mcpUrl: `http://127.0.0.1:${port}/mcp`,
      noBrowser: true,
      scopes: ['read'],
      onAuthUrl: (authUrlStr) => {
        const u = new URL(authUrlStr);
        expectedChallenge = u.searchParams.get('code_challenge') ?? '';
        capturedRedirectUri = u.searchParams.get('redirect_uri') ?? '';
        const state = u.searchParams.get('state') ?? '';
        // Simulate browser completing login and redirecting to loopback callback
        setTimeout(() => {
          fetch(`${capturedRedirectUri}?code=auth-code-999&state=${encodeURIComponent(state)}`).catch(() => {});
        }, 20);
      },
    });

    assert.equal(result.clientId, 'dyn-client-123');
    assert.equal(result.tokens.access_token, 'oauth-access-token-xyz');
  } finally {
    authServer.closeAllConnections();
    authServer.close();
  }
});
