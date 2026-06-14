import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { createServer } from 'http';

// ── Config ────────────────────────────────────────────────────────────────────
const PORT          = parseInt(process.env.PROXY_PORT    ?? '3002');
const ISSUER        = process.env.OAUTH_ISSUER           ?? `http://localhost:${PORT}`;
const CLIENT_ID     = process.env.OAUTH_CLIENT_ID        ?? 'mcp-client';
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET    ?? '';
const MCP_COMMAND   = process.env.MCP_COMMAND            ?? '';
const MCP_ARGS      = (process.env.MCP_ARGS ?? '').split(' ').filter(Boolean);

if (!CLIENT_SECRET) { console.error('ERROR: OAUTH_CLIENT_SECRET required'); process.exit(1); }
if (!MCP_COMMAND)   { console.error('ERROR: MCP_COMMAND required');          process.exit(1); }

// ── Stores ────────────────────────────────────────────────────────────────────
const authCodes    = new Map();
const accessTokens = new Map();

// sessionId -> { proc, pendingRequests: Map<id, {resolve,reject}>, buffer: string }
const sessions     = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────
const rand = () => crypto.randomBytes(32).toString('hex');

function verifyPKCE(verifier, challenge) {
  return crypto.createHash('sha256').update(verifier).digest('base64url') === challenge;
}

function requireBearer(req, res, next) {
  const h = req.headers['authorization'] ?? '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'unauthorized' });
  const exp = accessTokens.get(t);
  if (!exp || Date.now() > exp) { accessTokens.delete(t); return res.status(401).json({ error: 'token_expired' }); }
  next();
}

// ── Session / stdio process management ───────────────────────────────────────
function createSession(sessionId) {
  const proc = spawn(MCP_COMMAND, MCP_ARGS, { stdio: ['pipe', 'pipe', 'inherit'] });
  const session = { proc, pendingRequests: new Map(), buffer: '' };
  sessions.set(sessionId, session);

  proc.stdout.on('data', (chunk) => {
    session.buffer += chunk.toString();
    const lines = session.buffer.split('\n');
    session.buffer = lines.pop(); // keep incomplete line
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const msg = JSON.parse(trimmed);
        const pending = session.pendingRequests.get(msg.id);
        if (pending) {
          session.pendingRequests.delete(msg.id);
          pending.resolve(msg);
        }
      } catch {}
    }
  });

  proc.on('exit', () => {
    console.log(`Session ${sessionId} process exited`);
    sessions.delete(sessionId);
  });

  proc.on('error', (err) => console.error(`Session ${sessionId} process error:`, err));
  console.log(`Session created: ${sessionId}`);
  return session;
}

function sendToStdio(session, msg) {
  return new Promise((resolve, reject) => {
    const id = msg.id;
    if (id !== undefined && id !== null) {
      session.pendingRequests.set(id, { resolve, reject });
      setTimeout(() => {
        if (session.pendingRequests.has(id)) {
          session.pendingRequests.delete(id);
          reject(new Error('Request timeout'));
        }
      }, 30000);
    }
    try {
      session.proc.stdin.write(JSON.stringify(msg) + '\n');
      if (id === undefined || id === null) resolve(null); // notifications
    } catch (err) {
      reject(err);
    }
  });
}

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: '*', exposedHeaders: ['mcp-session-id'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// OAuth protected resource
app.use((req, res, next) => {
  if (req.path.startsWith('/.well-known/oauth-protected-resource')) {
    return res.json({ resource: ISSUER, authorization_servers: [ISSUER] });
  }
  next();
});

// OAuth discovery
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint:                `${ISSUER}/oauth/authorize`,
    token_endpoint:                        `${ISSUER}/oauth/token`,
    response_types_supported:              ['code'],
    code_challenge_methods_supported:      ['S256'],
    grant_types_supported:                 ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
  });
});

// Authorize
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

// Token
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
  res.json({ status: 'ok', sessions: sessions.size, tokens: accessTokens.size });
});

// ── MCP /mcp endpoint ─────────────────────────────────────────────────────────
app.post('/mcp', requireBearer, async (req, res) => {
  try {
    let sessionId = req.headers['mcp-session-id'];

    // Get or create session
    let session = sessionId ? sessions.get(sessionId) : null;
    if (!session) {
      sessionId = rand();
      session = createSession(sessionId);
    }

    const msg = req.body;
    const isNotification = msg.id === undefined || msg.id === null;

    res.setHeader('mcp-session-id', sessionId);

    if (isNotification) {
      // Fire and forget
      await sendToStdio(session, msg);
      res.status(202).end();
      return;
    }

    // Check if client accepts SSE
    const acceptsSSE = (req.headers['accept'] ?? '').includes('text/event-stream');

    if (acceptsSSE) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders();

      try {
        const response = await sendToStdio(session, msg);
        if (response) {
          res.write(`data: ${JSON.stringify(response)}\n\n`);
        }
      } catch (err) {
        res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: err.message } })}\n\n`);
      }
      res.end();
    } else {
      // Plain JSON response
      try {
        const response = await sendToStdio(session, msg);
        res.json(response ?? { jsonrpc: '2.0', id: msg.id, result: {} });
      } catch (err) {
        res.status(500).json({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: err.message } });
      }
    }
  } catch (err) {
    console.error('MCP handler error:', err);
    if (!res.headersSent) res.status(500).json({ error: 'internal_error', message: err.message });
  }
});

// GET /mcp for SSE stream (some clients use this)
app.get('/mcp', requireBearer, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  const sessionId = req.headers['mcp-session-id'] ?? rand();
  if (!sessions.has(sessionId)) createSession(sessionId);
  res.setHeader('mcp-session-id', sessionId);
  res.flushHeaders();
  // Keep alive
  const keepAlive = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => clearInterval(keepAlive));
});

app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

app.listen(PORT, () => {
  console.log(`mcp-oauth-proxy on :${PORT}/mcp`);
  console.log(`Command: ${MCP_COMMAND} ${MCP_ARGS.join(' ')}`);
  console.log(`Issuer:  ${ISSUER}`);
});
