# mcp-oauth-proxy

OAuth 2.0 Authorization Code + PKCE proxy for stdio MCP servers.

Wraps any MCP server exposed via SSE (e.g. via mcp-proxy) and adds OAuth 2.0
authentication compatible with claude.ai custom connectors.

## How it works

```
claude.ai → OAuth flow → mcp-oauth-proxy → upstream MCP SSE server → MCP stdio process
```

## Setup

```bash
npm install

PROXY_PORT=3100 \
UPSTREAM_URL=http://127.0.0.1:3001 \
OAUTH_ISSUER=https://yourdomain.example.com \
OAUTH_CLIENT_ID=mcp-client \
OAUTH_CLIENT_SECRET=your-secret \
npm start
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| PROXY_PORT | 3100 | Port to listen on |
| UPSTREAM_URL | http://127.0.0.1:3001 | Upstream MCP SSE server |
| OAUTH_ISSUER | http://localhost:3100 | Public HTTPS URL of this proxy |
| OAUTH_CLIENT_ID | mcp-client | OAuth client ID for claude.ai |
| OAUTH_CLIENT_SECRET | (required) | OAuth client secret for claude.ai |

## Endpoints

- `GET /.well-known/oauth-authorization-server` — OAuth discovery
- `GET /oauth/authorize` — Authorization endpoint
- `POST /oauth/token` — Token endpoint
- `GET /health` — Health check (public)
- `GET /sse` — MCP SSE stream (protected)
- `POST /messages` — MCP messages (protected)

## claude.ai configuration

In Settings > Integrations > Add custom connector:
- URL: `https://yourdomain.example.com/sse`
- OAuth Client ID: value of OAUTH_CLIENT_ID
- OAuth Client Secret: value of OAUTH_CLIENT_SECRET
