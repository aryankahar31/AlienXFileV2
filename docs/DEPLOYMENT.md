# Deploying personal OAuth

These steps keep the free-tier deployment model: Render Free web service, Neon Free PostgreSQL, private Vercel Blob, and optional Litterbox.

## 1. Generate the owner hash locally

Never put the plaintext password in Render or in this repository.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
flask --app flask_app owner-password-hash
```

The command prompts twice and prints one Argon2id hash. Treat the hash as a secret too.

## 2. Set Render environment variables

Required:

```text
DATABASE_URL=<Neon pooled URL>
BLOB_READ_WRITE_TOKEN=<Vercel Blob token>
SECRET_KEY=<stable random secret>
ALIENX_PUBLIC_BASE_URL=https://alienxfilev2.onrender.com
ALIENX_MCP_ENABLED=1
ALIENX_OAUTH_ENABLED=1
MCP_OAUTH_ENABLED=1
OWNER_USERNAME=owner
OWNER_PASSWORD_HASH=<printed Argon2id hash>
OAUTH_ISSUER=https://alienxfilev2.onrender.com
OAUTH_AUDIENCE=https://alienxfilev2.onrender.com/mcp
OAUTH_COOKIE_SECURE=1
```

Optional:

```text
MCP_API_KEY=<only if you need a static admin fallback>
ALIENX_SUPPORT_EMAIL=<public support address>
LITTERBOX_PROXY_URL=https://alienxfile-proxy.fly.dev
LITTERBOX_PROXY_SECRET=<Fly.io proxy secret, at least 24 characters>
```

Never set `MCP_ALLOW_ANONYMOUS` or `MCP_ALLOW_ANONYMOUS_WRITES` in a hosted
deployment. They exist for local development only; with them off, `/mcp`
refuses every request (HTTP 503) when no owner account and no API key are
configured.

`render.yaml` already declares the OAuth variables, marks `OWNER_PASSWORD_HASH` and `MCP_API_KEY` as dashboard secrets, and generates `SECRET_KEY` for new Blueprint instances. If the service already exists, confirm every value in the dashboard.

Do not enable `ALIENX_MCP_ENABLED=1` until `OWNER_PASSWORD_HASH` (or `MCP_API_KEY`, if intentionally using static auth) is set. The endpoint no longer falls back to anonymous access: without a credential it answers HTTP 503 and exposes no tools, so a forgotten environment variable can no longer publish the write tools to the internet.

## 3. Deploy

The start command runs schema setup before Gunicorn and loads the checked-in
Gunicorn configuration, which is what makes the forwarded scheme trustworthy:

```text
flask --app flask_app init-db && gunicorn -c gunicorn.conf.py flask_app:app
```

`gunicorn.conf.py` trusts `X-Forwarded-Proto` only when Render identifies the
service as a web service (`RENDER=true` and `RENDER_SERVICE_TYPE=web`), never
copies client-supplied `X-Forwarded-For` into the request environment, and
sets the worker/thread/timeout values the upload paths assume. The application
additionally applies `ProxyFix` for the scheme only when the same trusted
proxy configuration is present, so `X-Forwarded-Proto` can never mark a
directly exposed request as HTTPS. Real HTTPS responses carry
`Strict-Transport-Security`.

`init-db` creates the OAuth tables idempotently. No separate migration is required. After the deploy:

1. Open `https://alienxfilev2.onrender.com/.well-known/oauth-protected-resource`.
2. Open `https://alienxfilev2.onrender.com/.well-known/oauth-authorization-server`.
3. Confirm `issuer`, `authorization_endpoint`, and `token_endpoint` exactly match your public HTTPS origin.
4. Sign in at `/login` and approve a test client.
5. Call `/mcp` with the resulting token and run `tools/list`.

Changing `OAUTH_ISSUER` or `OAUTH_AUDIENCE` invalidates existing tokens and discovery URLs. Revoke old clients and reauthorize after a change.

## 4. Local development

SQLite defaults to `shares.sqlite3`. Set `OAUTH_ISSUER` and `OAUTH_AUDIENCE` explicitly for a stable local flow, for example:

```bash
export OAUTH_ISSUER=http://localhost:5000
export OAUTH_AUDIENCE=http://localhost:5000/mcp
export OWNER_USERNAME=owner
export OWNER_PASSWORD_HASH="$(flask --app flask_app owner-password-hash)"
export OAUTH_COOKIE_SECURE=0
flask --app flask_app run --debug
```

Some clients refuse `http://` issuers except for loopback development. Use a public HTTPS origin for real client testing.

## 5. Tests

```bash
.venv/bin/python -m unittest discover -v
```

Expected local result: all website, MCP, OAuth, multi-client, and pages tests pass; PostgreSQL tests skip unless `ALIENX_TEST_DATABASE_URL` is set. Never point the destructive PostgreSQL tests at production.

## 6. The Litterbox upload proxy

The proxy is a separate Fly.io service (`pa_proxy/`) that large browser uploads
use so the bytes never pass through the Render web service.

Required proxy environment (Fly.io secrets):

```text
LITTERBOX_PROXY_SECRET=<at least 24 characters, never a placeholder>
```

The proxy refuses to start when that secret is missing, shorter than 24
characters, or a placeholder value, so a misconfigured deployment fails loudly
instead of running with a guessable credential.

Browser uploads are authorised with a signed, single-use ticket that the web
service mints at `POST /api/litterbox-ticket` and binds to the file size. The
shared secret never reaches the browser. The proxy additionally rate limits
uploads per client address.

Optional proxy settings (defaults are sensible):

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXY_UPLOAD_RATE_LIMIT` | `30` | Browser uploads allowed per client address per window. |
| `PROXY_UPLOAD_RATE_WINDOW` | `3600` | Window seconds for the browser upload limit. |
| `PROXY_SERVER_RATE_LIMIT` | `600` | Server-to-server uploads allowed per client address per window. |
| `PROXY_SERVER_RATE_WINDOW` | `3600` | Window seconds for the server-to-server limit. |
| `PROXY_MAX_UPLOAD_BYTES` | `1073741824` | Hard cap on a single proxied upload. |
| `PROXY_MAX_TICKET_TTL` | `3600` | Longest ticket lifetime the proxy accepts. |

### Rotating the proxy secret

Rotation needs both ends and must be done by the owner:

1. Generate a new value (at least 24 characters) and store it in a password
   manager. Do not paste it into chat, issues, or the repository.
2. Update the Fly.io secret first: `flyctl secrets set LITTERBOX_PROXY_SECRET=<new value> -a alienxfile-proxy`.
3. Update the matching `LITTERBOX_PROXY_SECRET` environment variable in the
   Render dashboard and save; the web service restarts.
4. Between steps 2 and 3 the proxy rejects the web service's old secret, so
   proxied Litterbox uploads fail with 403 for that short window. Vercel
   uploads are unaffected.
5. Verify with a small Litterbox upload through the website and confirm the
   old value now fails.

## 7. Continuous integration and branch protection

`.github/workflows/ci.yml` runs the test suite on every push and pull
request: the SQLite suite on Python 3.12 and 3.13, and the same suite against
a PostgreSQL 17 service container. Dependencies are pinned in
`ci/requirements-lock.txt`. The workflow needs only `contents: read` and no
production secrets.

Recommended repository settings for `main` (the repository owner applies
these in GitHub Settings → Branches → Branch protection rules; they are not
changed by the workflow):

- Require status checks to pass before merging: `SQLite suite (Python 3.12)`,
  `SQLite suite (Python 3.13)` and `PostgreSQL 17 suite`.
- Require at least one approving review, and dismiss stale approvals when new
  commits are pushed.
- Require branches to be up to date before merging.
- Do not allow force pushes or branch deletion.

## 8. Operational notes

- Render Free sleeps after inactivity; the first OAuth or MCP request may be slow while the service wakes.
- There is no background token-cleanup worker. Expired OAuth rows are pruned opportunistically during normal OAuth activity, and unconsented stale dynamic clients are removed after 90 days.
- Back up the database like any other AlienXFile data. OAuth tables contain hashed credentials and metadata, not plaintext tokens or passwords.
- If `SECRET_KEY` changes, in-flight login forms fail CSRF validation and users simply reload `/login`.
- Rotate the owner password by generating a new hash and updating `OWNER_PASSWORD_HASH`; optionally revoke clients from `/account`.
