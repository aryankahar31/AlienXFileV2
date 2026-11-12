# Personal OAuth for AlienXFile MCP

AlienXFile uses a single-owner OAuth 2.1 authorization server so MCP clients can obtain scoped tokens without sharing a static API key. There is no public signup, email delivery, password reset, or multi-user account system.

## Components

| Component | Purpose |
| --- | --- |
| `oauth/constants.py` | Scope names and `OAUTH_SCHEMA` tables. |
| `oauth/security.py` | Argon2id owner passwords, token hashing, PKCE S256, CSRF, redirect/CIMD validation. |
| `oauth/store.py` | Clients, consents, sessions, authorization codes, access/refresh tokens, rotation, revocation. |
| `oauth/metadata.py` | Authorization-server and protected-resource metadata, `WWW-Authenticate` challenges. |
| `oauth/blueprint.py` | Discovery, registration, authorize, consent, token, revoke, login, account routes. |

OAuth tables are created by the existing `flask --app flask_app init-db` command and by SQLite's lazy schema setup. No extra migration command is required.

## Flow

1. A client reads `/.well-known/oauth-protected-resource` and is directed to `/.well-known/oauth-authorization-server`.
2. The client registers through `POST /oauth/register`, or uses an HTTPS client ID whose metadata document lists its redirect URIs.
3. `GET /oauth/authorize` validates `client_id`, an exactly registered `redirect_uri`, `response_type=code`, PKCE S256, scopes, and the requested `resource`.
4. If no owner session exists, the browser signs in at `/login` with CSRF protection and a per-IP/per-username rate limit.
5. The consent screen lists the exact client, redirect URI, and scopes. Approval is a CSRF-protected POST.
6. The authorization code is returned to the registered redirect URI with `state` and `iss`.
7. `POST /oauth/token` verifies the client, redirect URI, PKCE verifier, code lifetime, one-time use, consent, and resource audience before issuing opaque access/refresh tokens.
8. Refresh tokens rotate on every use. Replaying an old refresh token revokes the entire token family.
9. Owners can revoke a client from `/account`, which removes the consent and revokes its tokens.

## Security properties

- Access tokens, refresh tokens, authorization codes, client secrets, and owner sessions are stored only as SHA-256 hashes.
- Owner passwords are hashed with Argon2id (`time_cost=3`, 64 MiB memory). The CLI reads without echo.
- Access tokens are audience-bound to `OAUTH_AUDIENCE` (default `<issuer>/mcp`).
- Every OAuth request is rate limited per IP in a separate bucket. Login also has a per-username database bucket.
- OAuth responses and pages use `Cache-Control: no-store` and `X-Robots-Tag: noindex`.
- Owner session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when `OAUTH_COOKIE_SECURE=1`.
- Authorization errors are redirected only after the redirect URI is confirmed to belong to the client.
- `next` redirects after login accept only local paths; absolute, protocol-relative, backslash, and control-character variants fall back to `/account`.
- Dynamic registration and CIMD requests are bounded and rate limited; CIMD URLs require HTTPS, a path, port 443, public DNS, no credentials/query/fragment, and a matching `client_id`.
- MCP tools enforce scopes independently: `alienxfile:write` for writes, `alienxfile:read` for reads, and `alienxfile:admin` as a superset.

## Scopes

| Scope | Use |
| --- | --- |
| `alienxfile:read` | Read shares and check share metadata. |
| `alienxfile:write` | Create text and file shares. |
| `alienxfile:delete` | Reserved for future deletion-capable tools; no MCP tool currently exposes deletion. |
| `alienxfile:admin` | Superset used for owner/admin clients and future account operations. |

The default grant is `alienxfile:read alienxfile:write`. A client registered with a narrower scope cannot request more during authorization or refresh.

## Compatibility notes

- OAuth access tokens are opaque, not JWTs. Clients must treat them as bearer strings and use the discovery/token endpoints.
- Some client guides recommend non-rotating refresh tokens. This server rotates and rejects reuse; if a client does not persist the new refresh token it must reauthorize.
- Client UI labels differ across ChatGPT, Claude, Gemini, and generic MCP clients. Use the discovery URLs and standard endpoints rather than hardcoding a vendor flow.
- The issuer must remain stable. Changing `OAUTH_ISSUER` or `OAUTH_AUDIENCE` invalidates existing tokens and discovery URLs.

## Operational checks

```bash
flask --app flask_app init-db
flask --app flask_app owner-password-hash
python -m unittest test_oauth test_multiclient -v
```

Keep `OWNER_PASSWORD_HASH`, `SECRET_KEY`, and any `MCP_API_KEY` in secret storage. Never commit real values or production database URLs.
