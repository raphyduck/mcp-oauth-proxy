import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

// ── Config ────────────────────────────────────────────────────────────────────
const PORT          = parseInt(process.env.PROXY_PORT    ?? '3002');
const ISSUER        = process.env.OAUTH_ISSUER           ?? `http://localhost:${PORT}`;
const CLIENT_ID     = process.env.OAUTH_CLIENT_ID        ?? 'mcp-client';
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET    ?? '';
const MCP_COMMAND   = process.env.MCP_COMMAND            ?? '';
const MCP_ARGS      = (process.env.MCP_ARGS ?? '').split(' ').filter(Boolean);

if (!CLIENT_SECRET) { console.error('ERROR: OAUTH_CLIENT_SECRET required'); process.exit(1); }
if (!MCP_COMMAND)   { console.error('ERROR: MCP_COMMAND required');          process.exit(1); }

// ── In-memory stores ──────────────────────────────────────────────────────────
const authCodes    = new Map(); // code  -> { redirect_uri, code_challenge, exp }
const accessTokens = new Map(); // token -> exp
const sessions     = new Map(); // sessionId -> { transport, server }

// ── Helpers ───────────────────────────────────────────────────────────────────
const rand = () => crypto.randomBytes(32).toString('hex');

function verifyPKCE(verifier, challenge) {
  const b64 = crypto.createHash('sha256').update(verifier).digest('base64url');
  return b64 === challenge;
}

function requireBearer(req, res, next) {
  const header = req.headers['authorization'] ?? '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const exp = accessTokens.get(token);
  if (!exp || Date.now() > exp) { accessTokens.delete(token); return res.status(401).json({ error: 'token_expired' }); }
  next();
}

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: '*', exposedHeaders: ['mcp-session-id'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// OAuth protected resource metadata
app.use((req, res, next) => {
  if (req.path.startsWith('/.well-known/oauth-protected-resource')) {
    return res.json({ resource: ISSUER, authorization_servers: [ISSUER] });
  }
  next();
});

// OAuth discovery
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer:                                ISSUER,
    authorization_endpoint:                `${ISSUER}/oauth/authorize`,
    token_endpoint:                        `${ISSUER}/oauth/token`,
    response_types_supported:              ['code'],
    code_challenge_methods_supported:      ['S256'],
    grant_types_supported:                 ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
  });
});

// Authorization endpoint
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;
  if (client_id !== CLIENT_ID)          return res.status(400).json({ error: 'invalid_client' });
  if (response_type !== 'code')         return res.status(400).json({ error: 'unsupported_response_type' });
  if (code_challenge_method !== 'S256') return res.status(400).json({ error: 'invalid_request' });

  const code = rand();
  authCodes.set(code, { redirect_uri, code_challenge, exp: Date.now() + 600_000 });

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  res.redirect(302, url.toString());
});

// Token endpoint
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;
  if (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET)
    return res.status(401).json({ error: 'invalid_client' });
  if (grant_type !== 'authorization_code')
    return res.status(400).json({ error: 'unsupported_grant_type' });

  const stored = authCodes.get(code);
  if (!stored || Date.now() > stored.exp) { authCodes.delete(code); return res.status(400).json({ error: 'invalid_grant' }); }
  if (stored.redirect_uri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant' });
  if (!verifyPKCE(code_verifier, stored.code_challenge)) return res.status(400).json({ error: 'invalid_grant' });

  authCodes.delete(code);
  const token = rand();
  accessTokens.set(token, Date.now() + 86_400_000);
  res.json({ access_token: token, token_type: 'Bearer', expires_in: 86400 });
});

// Health
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', command: MCP_COMMAND, sessions: sessions.size, tokens: accessTokens.size });
});

// ── MCP /mcp endpoint (Streamable HTTP) ──────────────────────────────────────
app.all('/mcp', requireBearer, async (req, res) => {
  try {
    const sessionId = req.headers['mcp-session-id'];

    // Existing session
    if (sessionId && sessions.has(sessionId)) {
      const { transport } = sessions.get(sessionId);
      await transport.handleRequest(req, res);
      return;
    }

    // New session: spawn the stdio MCP process and wire it up
    const proc = spawn(MCP_COMMAND, MCP_ARGS, {
      stdio: ['pipe', 'pipe', 'inherit'],
    });

    proc.on('error', (err) => console.error('MCP process error:', err));
    proc.on('exit',  (code) => {
      console.log(`MCP process exited (${code})`);
      // Clean up session when process dies
      for (const [id, s] of sessions) {
        if (s.proc === proc) { sessions.delete(id); break; }
      }
    });

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => rand(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, proc });
        console.log(`Session created: ${id}`);
      },
    });

    // Wire stdio ↔ transport
    proc.stdout.on('data', (chunk) => {
      const lines = chunk.toString().split('\n').filter(l => l.trim().startsWith('{'));
      for (const line of lines) {
        try { transport.handleMessage(JSON.parse(line)); } catch {}
      }
    });

    transport.on('message', (msg) => {
      try { proc.stdin.write(JSON.stringify(msg) + '\n'); } catch {}
    });

    transport.on('close', () => {
      proc.kill();
    });

    await transport.handleRequest(req, res);
  } catch (err) {
    console.error('MCP handler error:', err);
    if (!res.headersSent) res.status(500).json({ error: 'internal_error' });
  }
});

app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

app.listen(PORT, () => {
  console.log(`mcp-oauth-proxy on :${PORT}/mcp`);
  console.log(`Command: ${MCP_COMMAND} ${MCP_ARGS.join(' ')}`);
  console.log(`Issuer:  ${ISSUER}`);
});
