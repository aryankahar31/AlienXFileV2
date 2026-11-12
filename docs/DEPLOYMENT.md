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
LITTERBOX_PROXY_SECRET=<Fly.io proxy secret>
```

`render.yaml` already declares the OAuth variables, marks `OWNER_PASSWORD_HASH` and `MCP_API_KEY` as dashboard secrets, and generates `SECRET_KEY` for new Blueprint instances. If the service already exists, confirm every value in the dashboard.

Do not enable `ALIENX_MCP_ENABLED=1` until `OWNER_PASSWORD_HASH` (or `MCP_API_KEY`, if intentionally using static auth) is set; otherwise the endpoint remains in anonymous development mode.

## 3. Deploy

The existing start command runs schema setup before Gunicorn:

```text
flask --app flask_app init-db && gunicorn flask_app:app
```

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

## 6. Operational notes

- Render Free sleeps after inactivity; the first OAuth or MCP request may be slow while the service wakes.
- There is no background token-cleanup worker. Expired OAuth rows are pruned opportunistically during normal OAuth activity, and unconsented stale dynamic clients are removed after 90 days.
- Back up the database like any other AlienXFile data. OAuth tables contain hashed credentials and metadata, not plaintext tokens or passwords.
- If `SECRET_KEY` changes, in-flight login forms fail CSRF validation and users simply reload `/login`.
- Rotate the owner password by generating a new hash and updating `OWNER_PASSWORD_HASH`; optionally revoke clients from `/account`.
