import express, { Request, Response, NextFunction } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { google } from "googleapis";
import { z } from "zod";
import crypto from "node:crypto";
import { GmailService } from "./gmail-service.js";
import { TokenStore } from "./token-store.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT || "3000", 10);
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD!;
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/userinfo.email",
];

// ---- Hardening feature flags (Phase B) ------------------------------------
// SETUP_ENABLED         : when not "true", the entire /setup + /oauth admin
//                         surface returns 404 (turn on only during onboarding).
// ENFORCE_IP_ALLOWLIST  : when "true", the /mcp endpoint only answers requests
//                         originating from Anthropic's published egress range.
// LOG_CLIENT_IP         : when "true", logs the detected client IP per /mcp
//                         request (used to empirically validate the allowlist).
// ENABLE_UNSUBSCRIBE    : when not "true", the unsubscribe_email tool is not
//                         registered (disabled by default).
const SETUP_ENABLED = process.env.SETUP_ENABLED === "true";
const ENFORCE_IP_ALLOWLIST = process.env.ENFORCE_IP_ALLOWLIST === "true";
const LOG_CLIENT_IP = process.env.LOG_CLIENT_IP === "true";
const ENABLE_UNSUBSCRIBE = process.env.ENABLE_UNSUBSCRIBE === "true";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const tokenStore = new TokenStore();

// ---------------------------------------------------------------------------
// Gmail service factory — exchanges stored refresh token for access token
// ---------------------------------------------------------------------------

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `${SERVER_URL}/oauth/callback`
  );
}

async function getGmailServiceForAccount(email: string): Promise<GmailService> {
  const refreshToken = tokenStore.getRefreshToken(email);
  if (!refreshToken) {
    throw new Error(
      `Account "${email}" is not connected. Use list_accounts to see connected accounts, or add it via the /setup page.`
    );
  }

  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({ refresh_token: refreshToken });

  const { token } = await oauth2.getAccessToken();
  if (!token) {
    throw new Error(
      `Failed to get access token for "${email}". The account may need to be re-authorized via /setup.`
    );
  }

  return new GmailService(token);
}

function resolveAccounts(account: string): string[] {
  if (account.toLowerCase() === "all") {
    const all = tokenStore.listAccounts().map((a) => a.email);
    if (all.length === 0) {
      throw new Error("No accounts connected. Add accounts via the /setup page.");
    }
    return all;
  }
  if (!tokenStore.hasAccount(account)) {
    const available = tokenStore.listAccounts().map((a) => a.email);
    throw new Error(
      `Account "${account}" is not connected. Available accounts: ${available.join(", ") || "none"}`
    );
  }
  return [account];
}

// ---------------------------------------------------------------------------
// MCP server factory — registers all tools
// ---------------------------------------------------------------------------

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "gmail-mcp-server",
    version: "1.0.0",
  });

  // ---- list_accounts ----
  server.tool(
    "list_accounts",
    "List all connected Gmail accounts. Use the email addresses returned here as the 'account' parameter in other tools.",
    {},
    async () => {
      const accounts = tokenStore.listAccounts();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                connected_accounts: accounts,
                usage_hint:
                  "Use any email address as the 'account' parameter, or use 'all' to query every account.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ---- list_emails ----
  server.tool(
    "list_emails",
    "Search and list emails. Supports Gmail search syntax (is:unread, from:, newer_than:7d, etc). Use account='all' to search across all connected accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .optional()
        .describe(
          "Gmail search query (e.g. 'is:unread', 'from:user@example.com newer_than:2d', 'subject:invoice')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to return per account (1-100)"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[] }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.listEmails(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({
            account: email,
            emails: [],
          });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(allResults, null, 2),
          },
        ],
      };
    }
  );

  // ---- get_email ----
  server.tool(
    "get_email",
    "Get the full content of a specific email including body, headers, and any unsubscribe links found.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const email = await gmail.getEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...email }, null, 2),
          },
        ],
      };
    }
  );

  // ---- archive_email ----
  server.tool(
    "archive_email",
    "Archive an email by removing it from the inbox. The email remains accessible via search or All Mail.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID to archive"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.archiveEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Email ${message_id} archived successfully.`,
            }),
          },
        ],
      };
    }
  );

  // ---- apply_label ----
  server.tool(
    "apply_label",
    "Apply a label to an email. Creates the label if it does not already exist.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
      label_name: z
        .string()
        .describe(
          "Label name to apply (e.g. 'Receipts', 'Follow Up'). Created automatically if it does not exist."
        ),
    },
    async ({ account, message_id, label_name }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.applyLabel(message_id, label_name);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Label "${label_name}" applied to email ${message_id}.`,
            }),
          },
        ],
      };
    }
  );

  // ---- unsubscribe_email (disabled by default — see ENABLE_UNSUBSCRIBE) ----
  // This tool has the server fetch URLs extracted from email content. That is a
  // server-side request (SSRF) surface, so it is off unless explicitly enabled.
  // The email-send path it used to contain has been removed from GmailService.
  if (ENABLE_UNSUBSCRIBE) {
    server.tool(
      "unsubscribe_email",
      "Attempt to unsubscribe from a mailing list. Tries List-Unsubscribe header (HTTP), then scans the email body for unsubscribe links.",
      {
        account: z
          .string()
          .describe("Email address of the account this message belongs to"),
        message_id: z
          .string()
          .describe("The Gmail message ID to unsubscribe from"),
      },
      async ({ account, message_id }) => {
        const gmail = await getGmailServiceForAccount(account);
        const result = await gmail.unsubscribeEmail(message_id);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ account, ...result }, null, 2),
            },
          ],
        };
      }
    );
  }

  // ---- batch_process ----
  server.tool(
    "batch_process",
    "Fetch a batch of emails matching a query for triage. Returns structured data so you can decide which actions to take on each email. Use account='all' to scan all accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .describe(
          "Gmail search query (e.g. 'is:unread category:promotions', 'newer_than:7d')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to fetch per account"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[] }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.batchProcess(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({ account: email, emails: [] });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                total: allResults.reduce((n, r) => n + r.emails.length, 0),
                query,
                results: allResults,
                hint: "Review each email and decide whether to archive, label, or skip. Use the individual tools with the correct account parameter.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
// Railway terminates TLS at its edge proxy; trust it so protocol/secure are correct.
app.set("trust proxy", true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// MCP secret-path guard — the /mcp endpoint lives at a secret URL
// ---------------------------------------------------------------------------
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;
if (!MCP_AUTH_TOKEN) {
  throw new Error("MCP_AUTH_TOKEN environment variable is required");
}
const MCP_PATH = `/mcp/${MCP_AUTH_TOKEN}`;

// ---------------------------------------------------------------------------
// Client IP + Anthropic egress allowlist (defense in depth for /mcp)
// Anthropic publishes a fixed outbound range for MCP connector traffic:
//   160.79.104.0/21  ->  base 160.79.104.0, mask 0xFFFFF800
// ---------------------------------------------------------------------------

function normalizeIp(ip: string): string {
  ip = (ip || "").trim();
  if (ip.startsWith("::ffff:")) ip = ip.slice(7); // IPv4-mapped IPv6
  return ip;
}

function getClientIp(req: Request): string {
  // Railway's Envoy edge sets X-Envoy-External-Address to the true external
  // client IP and overwrites any client-supplied value, so it is not spoofable.
  const envoy = req.headers["x-envoy-external-address"];
  if (typeof envoy === "string" && envoy.trim()) return normalizeIp(envoy);
  // Fall back to the rightmost XFF entry (the one the edge appended).
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length) return normalizeIp(parts[parts.length - 1]);
  }
  return normalizeIp(req.socket?.remoteAddress || "");
}

function ipv4ToInt(ip: string): number | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((n) => n > 255)) return null;
  return (
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
  );
}

const ANTHROPIC_BASE = ipv4ToInt("160.79.104.0")!;
const ANTHROPIC_MASK = 0xfffff800; // /21

function isAnthropicIp(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  return ((n & ANTHROPIC_MASK) >>> 0) === ((ANTHROPIC_BASE & ANTHROPIC_MASK) >>> 0);
}

function mcpIpGuard(req: Request, res: Response, next: NextFunction): void {
  const ip = getClientIp(req);
  if (LOG_CLIENT_IP) console.log(`[mcp] client ip: ${ip || "(unknown)"}`);
  if (!ENFORCE_IP_ALLOWLIST) {
    next();
    return;
  }
  if (isAnthropicIp(ip)) {
    next();
    return;
  }
  // Deny by default. Respond exactly like an unknown path so the endpoint
  // reveals nothing about itself to a caller outside the allowlist.
  res.status(404).send("Not found");
}

// ---------------------------------------------------------------------------
// Admin session + auth for the /setup and /oauth surface
//  - password checked in constant time, submitted via POST (never in the URL)
//  - success issues a short-lived HMAC-signed HttpOnly session cookie
//  - login is rate-limited with lockout
//  - the whole surface 404s unless SETUP_ENABLED === "true"
// ---------------------------------------------------------------------------

const SESSION_COOKIE = "mcp_session";
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
// Signing key derived from the admin password: rotating the password (or the
// key) instantly invalidates every outstanding session. Stable across restarts.
const SESSION_KEY = crypto.scryptSync(ADMIN_PASSWORD, "mcp-session-salt", 32);

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000; // 15 minutes
const loginAttempts = new Map<string, { count: number; lockUntil: number }>();

const pendingOAuthStates = new Map<string, number>(); // state -> expiry (ms)

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Compare against self to keep timing roughly uniform, then fail.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

function signSession(expMs: number): string {
  const payload = Buffer.from(JSON.stringify({ exp: expMs })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_KEY).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifySession(token: string | undefined): boolean {
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot < 0) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac("sha256", SESSION_KEY).update(payload).digest("base64url");
  if (!constantTimeEqual(sig, expected)) return false;
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return typeof parsed.exp === "number" && Date.now() < parsed.exp;
  } catch {
    return false;
  }
}

function parseCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx > -1) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

function newOAuthState(): string {
  const s = crypto.randomBytes(24).toString("base64url");
  pendingOAuthStates.set(s, Date.now() + 10 * 60 * 1000);
  return s;
}

function consumeOAuthState(s: string | undefined): boolean {
  if (!s) return false;
  const exp = pendingOAuthStates.get(s);
  if (exp === undefined) return false;
  pendingOAuthStates.delete(s);
  return Date.now() < exp;
}

function loginPage(message = ""): string {
  return `<!DOCTYPE html><html><head><title>Gmail MCP — Login</title></head>
    <body style="font-family:system-ui;max-width:400px;margin:80px auto;text-align:center">
      <h2>Admin Login</h2>
      ${message ? `<p style="color:#c0392b">${message}</p>` : ""}
      <form method="POST" action="/setup/login">
        <input type="password" name="key" placeholder="Admin password" autocomplete="current-password" style="padding:8px;width:100%;box-sizing:border-box;margin-bottom:12px" />
        <button type="submit" style="padding:8px 24px">Login</button>
      </form>
    </body></html>`;
}

// When setup is disabled, the entire admin surface is invisible.
function requireSetupEnabled(_req: Request, res: Response, next: NextFunction): void {
  if (!SETUP_ENABLED) {
    res.status(404).send("Not found");
    return;
  }
  next();
}

function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const cookies = parseCookies(req);
  if (verifySession(cookies[SESSION_COOKIE])) {
    next();
    return;
  }
  res.status(401).send(loginPage());
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

app.post("/setup/login", requireSetupEnabled, (req: Request, res: Response) => {
  const ip = getClientIp(req) || "unknown";
  const now = Date.now();
  const rec = loginAttempts.get(ip);

  if (rec && rec.lockUntil > now) {
    res.status(429).send("Too many attempts. Try again later.");
    return;
  }

  const provided = typeof req.body.key === "string" ? req.body.key : "";
  if (!constantTimeEqual(provided, ADMIN_PASSWORD)) {
    const base = rec && rec.lockUntil <= now ? { count: 0, lockUntil: 0 } : rec ?? { count: 0, lockUntil: 0 };
    base.count += 1;
    if (base.count >= MAX_LOGIN_ATTEMPTS) {
      base.lockUntil = now + LOGIN_LOCK_MS;
      base.count = 0;
    }
    loginAttempts.set(ip, base);
    res.status(401).send(loginPage("Incorrect password."));
    return;
  }

  loginAttempts.delete(ip);
  const cookie = signSession(now + SESSION_TTL_MS);
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${cookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`
  );
  res.redirect("/setup");
});

app.post("/setup/logout", requireSetupEnabled, (_req: Request, res: Response) => {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );
  res.redirect("/setup");
});

// ---------------------------------------------------------------------------
// Setup page — manage connected Gmail accounts
// ---------------------------------------------------------------------------

app.get("/setup", requireSetupEnabled, requireAdmin, (req: Request, res: Response) => {
  const accounts = tokenStore.listAccounts();
  const message = req.query.message as string | undefined;

  const accountRows = accounts.length > 0
    ? accounts
        .map(
          (a) => `
        <tr>
          <td>${a.email}</td>
          <td>${new Date(a.addedAt).toLocaleDateString()}</td>
          <td>
            <form method="POST" action="/setup/remove" style="display:inline">
              <input type="hidden" name="email" value="${a.email}" />
              <button type="submit" onclick="return confirm('Remove ${a.email}?')" style="color:red;background:none;border:1px solid red;padding:4px 12px;cursor:pointer">Remove</button>
            </form>
          </td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="3" style="text-align:center;color:#888">No accounts connected yet</td></tr>`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gmail MCP — Setup</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
        h1 { font-size: 1.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        th { font-weight: 600; border-bottom: 2px solid #ddd; }
        .btn { display: inline-block; padding: 10px 24px; background: #4285f4; color: white; text-decoration: none; border-radius: 6px; font-size: 14px; }
        .btn:hover { background: #3367d6; }
        .msg { padding: 12px; background: #e8f5e9; border-radius: 6px; margin-bottom: 16px; }
      </style>
    </head>
    <body>
      <h1>Gmail MCP Server — Setup</h1>
      ${message ? `<div class="msg">${message}</div>` : ""}
      <table>
        <thead><tr><th>Account</th><th>Added</th><th></th></tr></thead>
        <tbody>${accountRows}</tbody>
      </table>
      <a class="btn" href="/oauth/start">+ Add Gmail Account</a>
      <hr style="margin-top:40px;border:none;border-top:1px solid #eee" />
      <p style="color:#888;font-size:13px">
        Connected accounts: ${accounts.length}
        &nbsp;·&nbsp;
        <form method="POST" action="/setup/logout" style="display:inline"><button type="submit" style="background:none;border:none;color:#4285f4;cursor:pointer;padding:0;font-size:13px">Log out</button></form>
      </p>
    </body>
    </html>
  `);
});

app.post("/setup/remove", requireSetupEnabled, requireAdmin, (req: Request, res: Response) => {
  const email = req.body.email;

  if (email && tokenStore.hasAccount(email)) {
    tokenStore.removeAccount(email);
    res.redirect(`/setup?message=${encodeURIComponent(`Removed ${email}`)}`);
  } else {
    res.redirect(`/setup?message=${encodeURIComponent("Account not found")}`);
  }
});

// ---------------------------------------------------------------------------
// OAuth flow — server-managed Google auth
// ---------------------------------------------------------------------------

app.get("/oauth/start", requireSetupEnabled, requireAdmin, (_req: Request, res: Response) => {
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state: newOAuthState(), // random nonce, NOT the admin password
  });
  res.redirect(url);
});

app.get("/oauth/callback", requireSetupEnabled, async (req: Request, res: Response) => {
  const code = req.query.code as string;
  const state = req.query.state as string;
  const error = req.query.error as string;

  // The admin's session cookie is sent on this top-level redirect (SameSite=Lax).
  const cookies = parseCookies(req);
  if (!verifySession(cookies[SESSION_COOKIE])) {
    res.status(401).send(loginPage());
    return;
  }

  // Validate the CSRF state nonce we issued in /oauth/start.
  if (!consumeOAuthState(state)) {
    res.redirect(`/setup?message=${encodeURIComponent("Invalid or expired authorization request. Please try again.")}`);
    return;
  }

  if (error) {
    res.redirect(`/setup?message=${encodeURIComponent(`OAuth error: ${error}`)}`);
    return;
  }

  if (!code) {
    res.redirect(`/setup?message=${encodeURIComponent("No authorization code received")}`);
    return;
  }

  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);

    if (!tokens.refresh_token) {
      res.redirect(
        `/setup?message=${encodeURIComponent("No refresh token received. Try removing the app from your Google account permissions and re-adding.")}`
      );
      return;
    }

    oauth2.setCredentials(tokens);
    const oauth2Api = google.oauth2({ version: "v2", auth: oauth2 });
    const userInfo = await oauth2Api.userinfo.get();
    const email = userInfo.data.email;

    if (!email) {
      res.redirect(`/setup?message=${encodeURIComponent("Could not determine email address")}`);
      return;
    }

    tokenStore.addAccount(email, tokens.refresh_token);

    res.redirect(`/setup?message=${encodeURIComponent(`Successfully connected ${email}`)}`);
  } catch (err: any) {
    console.error("[oauth/callback] Error:", err?.message || err);
    res.redirect(`/setup?message=${encodeURIComponent(`Error: ${err?.message || "unknown error"}`)}`);
  }
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    accounts: tokenStore.size,
  });
});

// ---------------------------------------------------------------------------
// MCP transport — Streamable HTTP (stateless: each request gets a fresh server)
// The secret path is the primary gate; the IP allowlist is defense in depth.
// ---------------------------------------------------------------------------

app.post(MCP_PATH, mcpIpGuard, async (req: Request, res: Response) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless — no session tracking
    });

    const mcpServer = createMcpServer();
    await mcpServer.connect(transport);

    await transport.handleRequest(req, res, req.body);

    res.on("close", () => {
      mcpServer.close().catch(() => {});
      transport.close().catch(() => {});
    });
  } catch (err: any) {
    console.error("[mcp] Error handling request:", err?.message || err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: err.message },
        id: null,
      });
    }
  }
});

app.get(MCP_PATH, mcpIpGuard, async (_req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "SSE streams not supported in stateless mode. Use POST." },
    id: null,
  });
});

app.delete(MCP_PATH, mcpIpGuard, async (_req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Session management not used in stateless mode." },
    id: null,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`Gmail MCP server listening on port ${PORT}`);
  // NOTE: the real MCP endpoint is SERVER_URL + "/mcp/" + MCP_AUTH_TOKEN.
  // The token is intentionally NOT printed here so it never lands in logs.
  console.log(`  MCP endpoint:  ${SERVER_URL}/mcp/<MCP_AUTH_TOKEN>`);
  console.log(`  Setup page:    ${SERVER_URL}/setup  (enabled: ${SETUP_ENABLED})`);
  console.log(`  Health check:  ${SERVER_URL}/health`);
  console.log(`  IP allowlist:  ${ENFORCE_IP_ALLOWLIST ? "enforced (160.79.104.0/21)" : "off"}`);
  console.log(`  Unsubscribe:   ${ENABLE_UNSUBSCRIBE ? "enabled" : "disabled"}`);
  console.log(`  Accounts:      ${tokenStore.size}`);
});
