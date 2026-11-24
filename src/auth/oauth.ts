import { createHash, randomBytes } from 'node:crypto';
import { openBrowser, startLoopbackServer } from './browser.js';

export interface OAuthMetadata {
  issuer?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  code_challenge_methods_supported?: string[];
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface PkcePair {
  verifier: string;
  challenge: string;
  method: 'S256';
}

export function generatePkce(): PkcePair {
  const verifier = base64Url(randomBytes(32));
  const challenge = base64Url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge, method: 'S256' };
}

function base64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Extracts resource_metadata URL from a 401 WWW-Authenticate header (RFC 9728).
 */
export function parseResourceMetadataUrl(wwwAuthenticate?: string): string | undefined {
  if (!wwwAuthenticate) return undefined;
  const match = wwwAuthenticate.match(/resource_metadata\s*=\s*"([^"]+)"/i);
  return match?.[1];
}

/**
 * Discovers OAuth 2.1 Authorization Server metadata via:
 * 1. WWW-Authenticate `resource_metadata="..."` header (MCP Auth spec / RFC 9728)
 * 2. Path-scoped & root `/.well-known/oauth-protected-resource` (RFC 9728)
 * 3. Path-scoped & root `/.well-known/oauth-authorization-server` & OpenID Connect (RFC 8414)
 */
export async function discoverOAuthMetadata(
  mcpUrl: string,
  wwwAuthenticate?: string,
): Promise<OAuthMetadata | null> {
  const url = new URL(mcpUrl);
  const origin = url.origin;
  const cleanPath = url.pathname.replace(/\/+$/, '');

  // 1. Collect RFC 9728 Protected Resource Metadata candidates
  const prmCandidates: string[] = [];
  const headerPrm = parseResourceMetadataUrl(wwwAuthenticate);
  if (headerPrm) prmCandidates.push(headerPrm);
  if (cleanPath && cleanPath !== '/') {
    prmCandidates.push(`${origin}/.well-known/oauth-protected-resource${cleanPath}`);
  }
  prmCandidates.push(`${origin}/.well-known/oauth-protected-resource`);

  const authServers: string[] = [];
  for (const prmUrl of prmCandidates) {
    try {
      const prmRes = await fetch(prmUrl);
      if (!prmRes.ok) continue;
      const prm = (await prmRes.json()) as { authorization_servers?: string[] };
      if (Array.isArray(prm.authorization_servers)) {
        for (const asUrl of prm.authorization_servers) {
          if (typeof asUrl === 'string' && asUrl) authServers.push(asUrl);
        }
        if (authServers.length > 0) break;
      }
    } catch {
      // Try next PRM candidate
    }
  }

  if (authServers.length === 0) {
    authServers.push(cleanPath && cleanPath !== '/' ? `${origin}${cleanPath}` : origin);
  }

  // 2. Try RFC 8414 & OIDC discovery for each authorization server
  const candidates: string[] = [];
  for (const asEntry of authServers) {
    try {
      const asUrl = new URL(asEntry);
      const asOrigin = asUrl.origin;
      const asPath = asUrl.pathname.replace(/\/+$/, '');
      if (asPath && asPath !== '/') {
        candidates.push(`${asOrigin}/.well-known/oauth-authorization-server${asPath}`);
        candidates.push(`${asOrigin}/.well-known/openid-configuration${asPath}`);
        candidates.push(`${asOrigin}${asPath}/.well-known/openid-configuration`);
      }
      candidates.push(`${asOrigin}/.well-known/oauth-authorization-server`);
      candidates.push(`${asOrigin}/.well-known/openid-configuration`);
    } catch {
      // Ignore malformed auth server URL
    }
  }

  for (const endpoint of candidates) {
    try {
      const res = await fetch(endpoint);
      if (!res.ok) continue;
      const meta = (await res.json()) as Partial<OAuthMetadata>;
      if (meta.authorization_endpoint && meta.token_endpoint) {
        return meta as OAuthMetadata;
      }
    } catch {
      // Try next candidate
    }
  }
  return null;
}

/**
 * Dynamic Client Registration (RFC 7591) when supported by the MCP auth server.
 */
export async function registerDynamicClient(
  registrationEndpoint: string,
  redirectUri: string,
): Promise<string> {
  const res = await fetch(registrationEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'mcpguard CLI',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  });
  if (!res.ok) {
    throw new Error(`Dynamic OAuth client registration failed (HTTP ${res.status})`);
  }
  const data = (await res.json()) as { client_id?: string };
  if (!data.client_id) {
    throw new Error('OAuth registration response missing client_id');
  }
  return data.client_id;
}

export interface RunOAuthLoginOptions {
  mcpUrl: string;
  wwwAuthenticate?: string;
  metadata?: OAuthMetadata;
  clientId?: string;
  scopes?: string[];
  noBrowser?: boolean;
  timeoutMs?: number;
  onAuthUrl?: (url: string) => void;
}

export interface OAuthLoginResult {
  tokens: OAuthTokenResponse;
  metadata: OAuthMetadata;
  clientId: string;
  redirectUri: string;
}

/**
 * Executes a full OAuth 2.1 + PKCE S256 browser login flow with a local 127.0.0.1 callback.
 */
export async function runOAuthBrowserLogin(opts: RunOAuthLoginOptions): Promise<OAuthLoginResult> {
  const metadata = opts.metadata ?? (await discoverOAuthMetadata(opts.mcpUrl, opts.wwwAuthenticate));
  if (!metadata) {
    const hint = opts.wwwAuthenticate ? ` (WWW-Authenticate: ${opts.wwwAuthenticate})` : '';
    throw new Error(
      `This server returned 401 Unauthorized but does not expose OAuth 2.1 discovery metadata${hint}.\n` +
      `  If it uses a Bearer token or API key instead of OAuth, install it with:\n` +
      `    mcpguard install ${opts.mcpUrl} --auth bearer --token <YOUR_TOKEN>\n` +
      `    mcpguard install ${opts.mcpUrl} --auth api-key --api-key <YOUR_KEY>`,
    );
  }

  const loopback = await startLoopbackServer('/callback');
  try {
    let clientId = opts.clientId;
    if (!clientId && metadata.registration_endpoint) {
      clientId = await registerDynamicClient(metadata.registration_endpoint, loopback.redirectUri);
    }
    clientId ??= 'mcpguard-cli';

    const pkce = generatePkce();
    const state = base64Url(randomBytes(16));

    const authUrl = new URL(metadata.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', loopback.redirectUri);
    authUrl.searchParams.set('code_challenge', pkce.challenge);
    authUrl.searchParams.set('code_challenge_method', pkce.method);
    authUrl.searchParams.set('state', state);
    if (opts.scopes && opts.scopes.length > 0) {
      authUrl.searchParams.set('scope', opts.scopes.join(' '));
    }

    const urlStr = authUrl.toString();
    opts.onAuthUrl?.(urlStr);
    if (!opts.noBrowser) {
      openBrowser(urlStr);
    }

    const cb = await loopback.waitForCallback(opts.timeoutMs ?? 120_000);
    if (cb.state !== state) {
      throw new Error('OAuth state mismatch (possible CSRF); aborting token exchange.');
    }

    const tokens = await exchangeCodeForToken({
      tokenEndpoint: metadata.token_endpoint,
      clientId,
      code: cb.code,
      codeVerifier: pkce.verifier,
      redirectUri: loopback.redirectUri,
    });

    return { tokens, metadata, clientId, redirectUri: loopback.redirectUri };
  } finally {
    await loopback.close();
  }
}

export async function exchangeCodeForToken(params: {
  tokenEndpoint: string;
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<OAuthTokenResponse> {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: params.clientId,
    code: params.code,
    code_verifier: params.codeVerifier,
    redirect_uri: params.redirectUri,
  });

  const res = await fetch(params.tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`OAuth token exchange failed (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }
  const tokens = (await res.json()) as OAuthTokenResponse;
  if (!tokens.access_token) {
    throw new Error('OAuth token response missing access_token');
  }
  return tokens;
}
