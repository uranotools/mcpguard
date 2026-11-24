import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';

export interface LoopbackCallbackResult {
  code: string;
  state?: string;
}

export interface LoopbackServerHandle {
  port: number;
  redirectUri: string;
  waitForCallback(timeoutMs?: number): Promise<LoopbackCallbackResult>;
  close(): Promise<void>;
}

/**
 * Starts a local 127.0.0.1 loopback HTTP server on an ephemeral port to capture
 * OAuth 2.1 authorization code redirects cleanly.
 */
export async function startLoopbackServer(callbackPath = '/callback'): Promise<LoopbackServerHandle> {
  let resolveCallback: ((res: LoopbackCallbackResult) => void) | null = null;
  let rejectCallback: ((err: Error) => void) | null = null;

  const callbackPromise = new Promise<LoopbackCallbackResult>((resolve, reject) => {
    resolveCallback = resolve;
    rejectCallback = reject;
  });

  const server: Server = createServer((req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (reqUrl.pathname !== callbackPath) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('Not found');
      return;
    }

    const error = reqUrl.searchParams.get('error');
    const code = reqUrl.searchParams.get('code');
    const state = reqUrl.searchParams.get('state') ?? undefined;

    if (error) {
      const desc = reqUrl.searchParams.get('error_description') ?? error;
      res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' });
      res.end(`<html><body><h2>MCPGuard Authorization Failed</h2><p>${escapeHtml(desc)}</p></body></html>`);
      rejectCallback?.(new Error(`OAuth authorization failed: ${desc}`));
      return;
    }

    if (!code) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Missing authorization code');
      return;
    }

    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(
      '<html><body style="font-family:sans-serif;padding:2rem;"><h2>MCPGuard Login Complete</h2><p>You can safely close this tab and return to your terminal.</p></body></html>',
    );
    resolveCallback?.({ code, state });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const redirectUri = `http://127.0.0.1:${port}${callbackPath}`;

  return {
    port,
    redirectUri,
    async waitForCallback(timeoutMs = 120_000): Promise<LoopbackCallbackResult> {
      const timer = setTimeout(() => {
        rejectCallback?.(new Error(`OAuth browser callback timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      try {
        return await callbackPromise;
      } finally {
        clearTimeout(timer);
      }
    },
    async close(): Promise<void> {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * Opens a URL in the user's default browser across Windows, macOS, and Linux.
 */
export function openBrowser(url: string): boolean {
  try {
    if (process.platform === 'win32') {
      // Use rundll32 url.dll,FileProtocolHandler instead of `cmd /c start`,
      // because cmd.exe splits OAuth URLs at `&` characters.
      spawn('rundll32', ['url.dll,FileProtocolHandler', url], {
        detached: true,
        stdio: 'ignore',
      }).unref();
    } else if (process.platform === 'darwin') {
      spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    } else {
      spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
    }
    return true;
  } catch {
    return false;
  }
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
