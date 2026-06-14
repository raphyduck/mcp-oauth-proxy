import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import http from 'http';
import { URL } from 'url';

// ── Config ────────────────────────────────────────────────────────────────────
const PORT         = parseInt(process.env.PROXY_PORT   ?? '3100');
const UPSTREAM     = process.env.UPSTREAM_URL          ?? 'http://127.0.0.1:3001';
const ISSUER       = process.env.OAUTH_ISSUER          ?? `http://localhost:${PORT}`;
const CLIENT_ID    = process.env.OAUTH_CLIENT_ID       ?? 'mcp-client';
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET  ?? '';

if (!CLIENT_SECRET) {
  console.error('ERROR: OAUTH_CLIENT_SECRET is required');
  process.exit(1);
}

// ── In-memory stores ──────────────────────────────────────────────────────────
const authCodes    = new Map(); // code -> { redirect_uri, code_challenge, exp }
const accessTokens = new Map(); // token -> exp

// ── Helpers ───────────────────────────────────────────────────────────────────
const rand = () => crypto.randomBytes(32).toString('hex');

function verifyPKCE(verifier, challenge) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  const b64  = hash.toString('base64url');
  return b64 === challenge;
}

function requireBearer(req, res, next) {
  const header = req.headers['authorization'] ?? '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const exp = accessTokens.get(token);
  if (!exp || Date.now() > exp) {
    accessTokens.delete(token);
    return res.status(401).json({ error: 'token_expired' });
  }
  next();
}

// ── Proxy helper (SSE-aware) ──────────────────────────────────────────────────
function proxyRequest(req, res) {
  const target = new URL(UPSTREAM);
  const options = {
    hostname: target.hostname,
    port:     target.port || 80,
    path:     req.url,
    method:   req.method,
    headers:  { ...req.headers, host: target.host },
  };

  const upstream = http.request(options, (upRes) => {
    res.writeHead(upRes.statusCode, upRes.headers);
    upRes.pipe(res);
  });

  upstream.on('error', (err) => {
    console.error('Upstream error:', err.message);
    if (!res.headersSent) res.status(502).json({ error: 'bad_gateway' });
  });

  req.pipe(upstream);
}

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// OAuth discovery
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer:                             ISSUER,
    authorization_endpoint:             `${ISSUER}/oauth/authorize`,
    token_endpoint:                     `${ISSUER}/oauth/token`,
    response_types_supported:           ['code'],
    code_challenge_methods_supported:   ['S256'],
    grant_types_supported:              ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
  });
});

// Authorization endpoint
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;

  if (client_id !== CLIENT_ID)
    return res.status(400).json({ error: 'invalid_client' });
  if (response_type !== 'code')
    return res.status(400).json({ error: 'unsupported_response_type' });
  if (code_challenge_method !== 'S256')
    return res.status(400).json({ error: 'invalid_request', detail: 'only S256 supported' });

  const code = rand();
  authCodes.set(code, {
    redirect_uri,
    code_challenge,
    exp: Date.now() + 10 * 60 * 1000, // 10 min
  });

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
  if (!stored || Date.now() > stored.exp) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant' });
  }
  if (stored.redirect_uri !== redirect_uri)
    return res.status(400).json({ error: 'invalid_grant', detail: 'redirect_uri mismatch' });
  if (!verifyPKCE(code_verifier, stored.code_challenge))
    return res.status(400).json({ error: 'invalid_grant', detail: 'PKCE verification failed' });

  authCodes.delete(code);

  const token = rand();
  const exp   = Date.now() + 24 * 60 * 60 * 1000; // 24h
  accessTokens.set(token, exp);

  res.json({
    access_token: token,
    token_type:   'Bearer',
    expires_in:   86400,
  });
});

// Health (public)
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', upstream: UPSTREAM, sessions: accessTokens.size });
});

// MCP proxy (protected)
app.use('/sse',      requireBearer, proxyRequest);
app.use('/messages', requireBearer, proxyRequest);

// Fallback
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

app.listen(PORT, () => {
  console.log(`mcp-oauth-proxy listening on :${PORT}`);
  console.log(`Upstream MCP : ${UPSTREAM}`);
  console.log(`OAuth issuer : ${ISSUER}`);
  console.log(`OAuth discovery: ${ISSUER}/.well-known/oauth-authorization-server`);
});
