# Connecting MCP clients

Use the public HTTPS origin of the deployment. The examples below assume `https://alienxfilev2.onrender.com`; replace it with your `OAUTH_ISSUER` if different.

## Endpoints

| Purpose | URL |
| --- | --- |
| MCP endpoint | `https://alienxfilev2.onrender.com/mcp` |
| Protected-resource metadata | `https://alienxfilev2.onrender.com/.well-known/oauth-protected-resource` |
| Authorization-server metadata | `https://alienxfilev2.onrender.com/.well-known/oauth-authorization-server` |
| Authorization | `https://alienxfilev2.onrender.com/oauth/authorize` |
| Token | `https://alienxfilev2.onrender.com/oauth/token` |
| Dynamic registration | `https://alienxfilev2.onrender.com/oauth/register` |
| Revocation | `https://alienxfilev2.onrender.com/oauth/revoke` |

`POST /mcp` must be enabled with `ALIENX_MCP_ENABLED=1`. With an owner configured, unauthenticated calls return HTTP 401 and:

```text
WWW-Authenticate: Bearer resource_metadata="https://alienxfilev2.onrender.com/.well-known/oauth-protected-resource"
```

## Generic OAuth-capable client

1. Add an MCP server with URL `https://alienxfilev2.onrender.com/mcp`.
2. Let the client use OAuth discovery. If it asks for endpoints, enter the values above.
3. The browser opens the AlienXFile owner sign-in page. Sign in with `OWNER_USERNAME` and the password whose Argon2id hash is in `OWNER_PASSWORD_HASH`.
4. Approve the requested scopes. A read-only client needs `alienxfile:read`; uploads/text shares need `alienxfile:write`.
5. The client stores the access token and the rotated refresh token. If it cannot rotate refresh tokens, reauthorize when the access token expires (15 minutes by default).

Clients that require Dynamic Client Registration can use `POST /oauth/register`. Public clients must use PKCE S256 and `token_endpoint_auth_method: "none"`; confidential clients may use `client_secret_basic` or `client_secret_post`.

## ChatGPT

Add a custom connector/MCP server with the `/mcp` URL. ChatGPT should follow the 401 challenge to the protected-resource metadata and complete OAuth. Keep the browser session on the same origin; do not configure a localhost issuer for a publicly hosted service.

`upload_file` keeps the `openai/fileParams` integration for desktop-web attachments. Files larger than `MCP_MAX_UPLOAD_BYTES` must be uploaded on the website and shared by code.

## Claude

Add a custom integration/connector with the `/mcp` URL and OAuth discovery enabled. If the client supports manual OAuth configuration, use the authorization/token endpoints above and request `alienxfile:read` and/or `alienxfile:write`.

## Gemini

Use the MCP server URL and the standard OAuth discovery endpoints. Gemini's guide may prefer refresh tokens that do not rotate; this server rotates them for replay detection. If Gemini rejects the rotated token, reauthorize the connection. Do not weaken rotation just for one client.

## curl checks

Discovery does not require authentication:

```bash
curl -s https://alienxfilev2.onrender.com/.well-known/oauth-protected-resource
curl -s https://alienxfilev2.onrender.com/.well-known/oauth-authorization-server
```

After completing OAuth in a client, verify the token with:

```bash
curl -s https://alienxfilev2.onrender.com/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Never paste real access or refresh tokens into tickets, logs, or screenshots.

## Troubleshooting

- **401 from `/mcp`** — the token is missing, expired, revoked, or issued for a different `OAUTH_AUDIENCE`.
- **403 with `insufficient_scope`** — the connection lacks the scope required by that tool; reauthorize with the needed scope.
- **`invalid_client`** — the client ID is unknown, dynamic registration is disabled, or the client secret is wrong.
- **`invalid_grant` on refresh** — the refresh token was already rotated, expired, revoked, or belongs to another client. Reauthorize.
- **`invalid_target`** — the client requested a resource other than `OAUTH_AUDIENCE`.
- **Consent page loops to login** — cookies are blocked, `SECRET_KEY` changed after the form was issued, or the clock is badly skewed.
- **`temporarily_unavailable` / 429** — the OAuth endpoint bucket is exhausted; respect `Retry-After`.
