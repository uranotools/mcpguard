import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname, homedir, userInfo } from 'node:os';
import { dirname, join } from 'node:path';

interface EncryptedVaultPayload {
  version: number;
  iv: string;
  tag: string;
  data: string;
}

/**
 * Local encrypted credentials vault (AES-256-GCM) stored in ~/.mcpguard/credentials.json.
 * Uses a machine-derived key (or MCPGUARD_VAULT_KEY env override) so raw API keys and OAuth
 * tokens are never persisted in plaintext config files.
 */
export class SecretVault {
  private readonly filePath: string;
  private readonly key: Buffer;

  constructor(baseDir?: string, passphrase?: string) {
    const dir = baseDir ?? join(homedir(), '.mcpguard');
    this.filePath = join(dir, 'credentials.json');
    const material =
      passphrase ??
      process.env.MCPGUARD_VAULT_KEY ??
      `mcpguard-v1:${hostname()}:${safeUsername()}:${dir}`;
    this.key = scryptSync(material, 'uranotools-mcpguard-salt', 32);
  }

  private readAll(): Record<string, string> {
    if (!existsSync(this.filePath)) return {};
    try {
      const raw = JSON.parse(readFileSync(this.filePath, 'utf8')) as EncryptedVaultPayload;
      if (!raw || raw.version !== 1 || !raw.iv || !raw.tag || !raw.data) return {};
      const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(raw.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(raw.tag, 'hex'));
      const plain = Buffer.concat([
        decipher.update(Buffer.from(raw.data, 'hex')),
        decipher.final(),
      ]).toString('utf8');
      return JSON.parse(plain) as Record<string, string>;
    } catch {
      return {};
    }
  }

  private writeAll(records: Record<string, string>): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(records), 'utf8'),
      cipher.final(),
    ]);
    const payload: EncryptedVaultPayload = {
      version: 1,
      iv: iv.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
      data: encrypted.toString('hex'),
    };
    writeFileSync(this.filePath, JSON.stringify(payload, null, 2), { mode: 0o600 });
  }

  set(ref: string, secret: string): void {
    const all = this.readAll();
    all[ref] = secret;
    this.writeAll(all);
  }

  get(ref: string): string | undefined {
    const all = this.readAll();
    return all[ref];
  }

  delete(ref: string): boolean {
    const all = this.readAll();
    if (!(ref in all)) return false;
    delete all[ref];
    this.writeAll(all);
    return true;
  }

  listRefs(): string[] {
    return Object.keys(this.readAll());
  }
}

function safeUsername(): string {
  try {
    return userInfo().username;
  } catch {
    return 'user';
  }
}
