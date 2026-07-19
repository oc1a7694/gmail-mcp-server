import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Encrypted token store
//
// Persistence strategy (in priority order):
// 1. File on disk (works if volume is mounted or running locally)
// 2. TOKENS_DATA env var (base64-encoded JSON — survives Railway redeploys)
//
// On save: writes to both file AND logs the env var value so you can copy it.
// On load: tries file first, falls back to TOKENS_DATA env var.
// ---------------------------------------------------------------------------

interface StoredAccount {
  email: string;
  refreshToken: string; // encrypted
  addedAt: string;
}

interface StoreData {
  accounts: StoredAccount[];
}

const ALGORITHM = "aes-256-gcm";

function dataDir(): string {
  return process.env.DATA_DIR || "./data";
}

function dataFile(): string {
  return join(dataDir(), "accounts.json");
}

function deriveKey(): Buffer {
  const secret = process.env.ENCRYPTION_KEY;
  if (!secret) {
    throw new Error("ENCRYPTION_KEY environment variable is required");
  }
  return scryptSync(secret, "gmail-mcp-salt", 32);
}

function encrypt(plaintext: string): string {
  const key = deriveKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [iv.toString("hex"), tag.toString("hex"), encrypted.toString("hex")].join(":");
}

function decrypt(blob: string): string {
  const key = deriveKey();
  const [ivHex, tagHex, encHex] = blob.split(":");
  const decipher = createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(ivHex, "hex")
  );
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(encHex, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

export class TokenStore {
  private accounts = new Map<string, StoredAccount>();

  constructor() {
    this.load();
  }

  private load(): void {
    // Try file first
    try {
      const dir = dataDir();
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const file = dataFile();
      if (existsSync(file)) {
        const raw: StoreData = JSON.parse(readFileSync(file, "utf8"));
        for (const acct of raw.accounts ?? []) {
          this.accounts.set(acct.email, acct);
        }
        console.log(`[token-store] Loaded ${this.accounts.size} account(s) from file`);
        return;
      }
    } catch (err) {
      console.error("[token-store] Failed to load from file", err);
    }

    // Fall back to TOKENS_DATA env var
    const envData = process.env.TOKENS_DATA;
    if (envData) {
      try {
        const raw: StoreData = JSON.parse(
          Buffer.from(envData, "base64").toString("utf8")
        );
        for (const acct of raw.accounts ?? []) {
          this.accounts.set(acct.email, acct);
        }
        console.log(`[token-store] Loaded ${this.accounts.size} account(s) from TOKENS_DATA env var`);
        // Write to file so subsequent saves work
        this.saveToFile();
        return;
      } catch (err) {
        console.error("[token-store] Failed to parse TOKENS_DATA env var", err);
      }
    }

    console.log("[token-store] No existing accounts found — starting fresh");
  }

  private saveToFile(): void {
    try {
      const dir = dataDir();
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(
        dataFile(),
        JSON.stringify(
          { accounts: Array.from(this.accounts.values()) } satisfies StoreData,
          null,
          2
        )
      );
    } catch (err) {
      console.error("[token-store] Failed to write file", err);
    }
  }

  private save(): void {
    // Persist to the data file only. The encrypted TOKENS_DATA blob is NO
    // LONGER logged to the console (it used to be printed on every save, which
    // put it into Railway's log stream). Export it deliberately via
    // getTokensDataForExport() if a manual backup is ever needed.
    this.saveToFile();
  }

  /** Returns base64-encoded token data for copying to env var */
  getTokensDataForExport(): string {
    const data: StoreData = { accounts: Array.from(this.accounts.values()) };
    return Buffer.from(JSON.stringify(data)).toString("base64");
  }

  addAccount(email: string, refreshToken: string): void {
    this.accounts.set(email, {
      email,
      refreshToken: encrypt(refreshToken),
      addedAt: new Date().toISOString(),
    });
    this.save();
    console.log(`[token-store] Added account: ${email}`);
  }

  removeAccount(email: string): boolean {
    const deleted = this.accounts.delete(email);
    if (deleted) {
      this.save();
      console.log(`[token-store] Removed account: ${email}`);
    }
    return deleted;
  }

  getRefreshToken(email: string): string | null {
    const acct = this.accounts.get(email);
    if (!acct) return null;
    try {
      return decrypt(acct.refreshToken);
    } catch (err) {
      console.error(`[token-store] Failed to decrypt token for ${email}`, err);
      return null;
    }
  }

  listAccounts(): { email: string; addedAt: string }[] {
    return Array.from(this.accounts.values()).map((a) => ({
      email: a.email,
      addedAt: a.addedAt,
    }));
  }

  hasAccount(email: string): boolean {
    return this.accounts.has(email);
  }

  get size(): number {
    return this.accounts.size;
  }
}
