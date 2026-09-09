# AlienXFile V2

Temporary file and text sharing built with Flask, PostgreSQL (or SQLite for local/PythonAnywhere use), and private [Vercel Blob](https://vercel.com/docs/vercel-blob) storage. The responsive pages use HTML, CSS, and JavaScript, with no frontend build step. The original Litterbox integration remains available when no Blob token is configured.

- Share files or text using a five-digit code, including leading zeros, or a share link.
- Choose expiration after 1, 12, 24, or 72 hours.
- Copy a link or scan a QR code generated locally by the app; no external QR service receives the link.
- Select multiple files; the browser uploads them sequentially, with one file per `/upload` API request. Flask streams each file to the configured storage provider.
- View share details at `/share/<code>`. `/download` accepts a code; `/download/<code>` streams private files after checking expiry, redirects legacy Litterbox files, or displays shared text.
- Text is limited to 100,000 characters and stored in the database. File metadata, provider URLs, codes, expiration times, and per-IP rate-limit records also live there; file payloads remain in the configured object store.
- Uploads require JavaScript. Code lookup and the download/details page work without it; copying and local-time formatting are progressive enhancements.

The progress bar measures browser-to-app transfer only. Reaching 100% does not mean the storage provider has accepted the file. Cancel stops the browser request and remaining queue, but does not delete a file the server has already stored or may still finish storing.

## Upload Limits

| Layer | Limit or constraint |
| --- | --- |
| Flask per-file hard ceiling | 1 GB, decimal: `1,000,000,000` bytes. `ALIENX_UPLOAD_MAX_BYTES` can lower this, not raise it. |
| Flask HTTP request cap | Configured file limit plus `1,000,000` bytes for multipart overhead. Default: `1,001,000,000` bytes (1 GB + 1 MB), for the whole request. |
| Litterbox | The [official homepage](https://litterbox.catbox.moe/) advertises a 1 GB upload limit. This is a provider limit, not an end-to-end hosting guarantee. |
| Prepared Render configuration / PythonAnywhere example | `95,000,000` bytes per file (95 MB, decimal), giving a Flask request cap of `96,000,000` bytes. This is an initial operational cap, not a claimed Render maximum. |

The frontend displays the configured file limit, but a proxy, timeout, disk quota, or provider can reject a smaller upload. Direct API clients may submit up to 10 files in a request, but their combined multipart body must still fit the request cap. The browser avoids this combined-size issue by sending one file per request; it does not chunk individual files.

**A real 1 GB upload through Render remains unverified.** Render's cited free-service documentation does not publish an ingress body-size maximum; neither the 1 GB application ceiling nor the initial 95 MB operational cap proves host support. Temporary disk space, memory, request duration, and outbound transfer to Litterbox also constrain uploads. Vercel is not used: its [4.5 MB Functions payload limit](https://vercel.com/docs/functions/limitations#request-body-size) does not fit this upload-proxy path.

**A real 1 GB upload through PythonAnywhere is not guaranteed.** Raising Flask's limit or the browser timeout does not override any of these hosting constraints:

- A [PythonAnywhere staff reply dated June 5, 2023](https://www.pythonanywhere.com/forums/topic/33086/#id_post_112765) states a request-body limit of "100Mb". Treat this as an approximate 100 MB HTTP request cap, not an exact byte contract or a current plan guarantee. Confirm current limits with support. The 95 MB example leaves conservative multipart headroom below that reported cap.
- PythonAnywhere documents a [five-minute web-worker timeout](https://help.pythonanywhere.com/pages/AsyncInWebApps/). This app forwards files synchronously; longer client timeouts cannot keep a worker alive beyond the host's limit.
- PythonAnywhere's [disk quota documentation](https://help.pythonanywhere.com/pages/DiskQuota/) lists 512 MiB for free accounts and counts `/tmp` usage. Large incoming uploads spool to temporary files even though forwarding uses a streaming multipart encoder. Code, dependencies, SQLite, temporary files, and concurrent uploads compete for disk space; paid plans have different quotas.
- A 100 MiB upload limit shown in PythonAnywhere's Files dashboard concerns uploading project files through that dashboard. It is separate from this application's file limit and the web proxy's HTTP request cap. MB and MiB are different units.

For actual 1 GB transfers, change the upload path, hosting, or storage architecture to one that supports the required request size, duration, and temporary storage. A Flask configuration tweak is insufficient. Direct browser-to-storage uploads would require verified provider CORS support and an appropriate share-registration flow; that route is **unverified and not implemented** here. There is no resumable/chunked upload implementation. These docs do not claim a deployed or tested real 1 GB transfer.

## Local Setup

`requirements.txt` specifies Flask `>=3.1,<4`, requests `>=2.32,<3`, requests-toolbelt `>=1.0,<2` for streaming multipart uploads, qrcode `>=8.0,<9` for SVG QR codes (no Pillow needed), psycopg[binary] `>=3.2,<4` for PostgreSQL, and gunicorn `>=23,<24` for Render. The local/PythonAnywhere examples use Python 3.11; the prepared Render runtime uses Python 3.14.3.

For local SQLite, leave `DATABASE_URL` and `RENDER` unset. An external PostgreSQL `DATABASE_URL` takes precedence over `ALIENX_DATABASE`; SQLite fallback is **only for local development and PythonAnywhere**, not Render. Setting `RENDER=true` without `DATABASE_URL` stops startup instead of silently storing data on an ephemeral filesystem.

Run from the project directory on Linux/macOS:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
flask --app flask_app run
```

On Windows, create the environment with your installed Python and activate it with `.venv\Scripts\Activate.ps1` in PowerShell. Open `http://127.0.0.1:5000`. The Flask development server is for local development, not public deployment.

Run the Python tests from the project directory after installing the dependencies:

```bash
python -m unittest discover -v
```

The optional PostgreSQL integration tests in `test_postgres.py` use `ALIENX_TEST_DATABASE_URL` and isolated test schemas; they skip when the variable is unset. Supply a direct, unpooled connection URL privately for an authorized test database whose role can create/drop schemas. Neon pooled connections reject the tests' schema-specific startup options; the application itself does not use those options. Run `python -m unittest test_postgres -v` to exercise that backend. Never use a production database for destructive testing.

Local tests are not evidence that Render, PythonAnywhere, or Litterbox accepts a real 1 GB upload.

## Render Free + Neon Free

The Render service **AlienXFileV2** is at <https://alienxfilev2.onrender.com>, linked to <https://github.com/aryankahar31/AlienXFileV2>. This configuration uses Render Free, an external Neon database, and a private Vercel Blob store on the Hobby plan, not a paid disk. Credentials belong only in the service's secret environment variables, never in the repository. Litterbox returned HTTP 403 during live verification, so this deployment uses Vercel Blob instead.

- [Neon Free pricing](https://neon.com/pricing) currently requires no credit card and includes 0.5 GB storage per project and 100 CU-hours per project per month. It is not a time-limited trial, but quotas and scale-to-zero still apply; monitor database usage, including shared text and rate-limit rows.
- [Render Free services](https://render.com/docs/free) sleep after 15 minutes without inbound traffic and can take about a minute to wake. Filesystem changes are lost on sleep, restart, or redeploy, and Free has no persistent disk. Neon keeps database state outside the web service; temporary upload files are not durable.
- Avoid **Render Free Postgres**, which expires after 30 days. Render Free web services share 750 instance hours per workspace per month. Outbound bandwidth and build-pipeline allowances depend on current workspace limits; check the dashboard rather than assuming a fixed 5 GB allowance. Forwarding files to Litterbox consumes outbound traffic, and unusually high service-initiated traffic can also trigger suspension. Without a payment method, exhausted allowances can suspend services or disable new builds; with one, overages can be billed. Do not add payment details or upgrade under the free-only choice.
- [Vercel Blob Hobby](https://vercel.com/docs/vercel-blob/usage-and-pricing#hobby) is free within its quotas and blocks usage instead of charging overages. Blob quotas are shared across the account's stores. Private file downloads pass through Render, so both services' transfer limits apply.

`render.yaml` describes `name: AlienXFileV2`, `plan: free`, `region: singapore`, Python 3.14.3, build command `pip install -r requirements.txt`, `DATABASE_URL` with `sync: false` (secret supplied separately), and `ALIENX_UPLOAD_MAX_BYTES: '95000000'`. Its start command is:

```bash
flask --app flask_app init-db && gunicorn flask_app:app
```

PostgreSQL schema initialization is explicit: `init-db` must succeed before workers start; it is not performed lazily by requests. Gunicorn automatically loads `gunicorn.conf.py` from the project working directory, binding `0.0.0.0:$PORT` with one worker, two threads, and a 240-second timeout. In Render mode, HTTPS scheme handling trusts only `X-Forwarded-Proto`, and per-client rate limiting uses `CF-Connecting-IP`, not `X-Forwarded-For`. Enable that trust **only behind Render's public proxy**, never for a directly exposed server or an alternate untrusted ingress.

### Setup

1. Sign up at <https://neon.com/signup>, select **Free**, and create a project in the available region nearest Render Singapore (Singapore if offered). Do not select a paid plan or add a card; stop if free setup is unavailable.
2. In Neon's project **Connect** dialog, select the database/role and enable connection pooling. Copy the pooled PostgreSQL connection URL with TLS required (`sslmode=require`; preserve any additional security parameters Neon supplies). Put the actual URL only in the existing Render service's dashboard secret environment variable `DATABASE_URL`, never in chat, source, `render.yaml`, screenshots, or logs.
3. Create a **Private** Vercel Blob store in Singapore (`sin1`) on a Hobby account. Set its static read/write token in Render as `BLOB_READ_WRITE_TOKEN`. Do not put that token in browser code or use a public store. The app derives the allowed private hostname from the token, and never sends the token to arbitrary download URLs. Without this setting, uploads use Litterbox, which may reject the deployment's requests.
4. Before publishing, update the existing Render service settings to match the configuration: Free instance, `PYTHON_VERSION=3.14.3`, project-root working directory, the build/start commands above, and `ALIENX_UPLOAD_MAX_BYTES=95000000`. Confirm the region is Singapore; if changing it requires a replacement service, obtain authorization first. Render supplies `RENDER=true` and `RENDER_SERVICE_TYPE=web`. Disable automatic deploys while preparing settings so a repository update cannot publish prematurely. A Blueprint file does **not** automatically update an existing dashboard-configured service unless that service is managed by the Blueprint.
5. Publish reviewed changes to the intended repository/branch and manually deploy the existing service. Confirm schema initialization succeeds before Gunicorn starts. No second web service, Render database, or paid resource is needed.
6. Verify a small text share and a small file upload/download over HTTPS, five-digit lookup (including leading zeros), and QR links. Restart the service and confirm unexpired shares still work from Neon. Check rate limits from two different client IPs so clients do not all share the proxy's allowance; excess requests must return 429 with `Retry-After`. Inspect global security/cache headers on success and error responses without logging credentials or tokens. These smoke checks do not verify 95 MB or 1 GB transfers.

## PythonAnywhere Setup

For this alternative host, use **manual configuration**, with project files at `/home/ALIENXFILEV2/mysite`. If deploying under another username, replace `ALIENXFILEV2` consistently in every path below. Leave `DATABASE_URL` and `RENDER` unset for this SQLite configuration.

1. In the Files tab, create or open `/home/ALIENXFILEV2/mysite` and upload the runtime files listed below, preserving the `templates` and `static` directories.
2. In the Web tab, add a new web app and choose **Manual configuration**. Choose an available Python version compatible with the requirements. The example below uses **Python 3.11**; the console interpreter, virtual environment, and Web app Python version must match. Do not select a different Web version just because the console has `python3.11`.
3. Open a **Bash console** and create the virtual environment and install dependencies using the commands below.
4. In the Web tab, set **Source code** and **Working directory** to `/home/ALIENXFILEV2/mysite`, and **Virtualenv** to exactly `/home/ALIENXFILEV2/venv` (not its `bin` directory or `activate` script).
5. Open the Web tab's **WSGI configuration file** and replace its sample application configuration with the WSGI block below. Set all environment variables before importing `flask_app`.
6. If configuring a Web static-file mapping, map only `/static/` to `/home/ALIENXFILEV2/mysite/static/`. Never expose the home directory, project root, or database through a static mapping.
7. Reload the Web app. Check the error log if startup fails, confirm its HTTPS address works, and enable **Web → Security → Force HTTPS**. This keeps uploads, share links, and QR URLs on HTTPS; leave this enabled.
8. Verify a small text share and small file upload/download. Confirm outbound access to Litterbox on your account/plan; do not assume provider access or large uploads work without testing.

Runtime files to deploy:

```text
/home/ALIENXFILEV2/mysite/
    flask_app.py
    requirements.txt
    templates/
        index.html
        download.html
    static/
        upload.js
```

Python and JavaScript test files are for development, not required for deployment. In particular, deploy `static/upload.js`, not static JavaScript test files. Do not upload a local SQLite database over the live database.

Bash console setup, using the same Python version selected in Web:

```bash
python3.11 -m venv /home/ALIENXFILEV2/venv
source /home/ALIENXFILEV2/venv/bin/activate
python -m pip install -r /home/ALIENXFILEV2/mysite/requirements.txt
```

WSGI configuration:

```python
import os
import sys

sys.path.insert(0, '/home/ALIENXFILEV2/mysite')

os.environ['ALIENX_DATABASE'] = '/home/ALIENXFILEV2/shares.sqlite3'
os.environ['ALIENX_PYTHONANYWHERE'] = '1'
os.environ['ALIENX_UPLOAD_MAX_BYTES'] = '95000000'

from flask_app import app as application
```

`ALIENX_DATABASE` is deliberately an absolute path **outside both the code directory and static files**, so uploading replacement code does not overwrite share data. The account must be able to write the database and its parent directory. Exporting variables in a Bash console alone does not configure the Web worker; keep these settings in WSGI before the import, then reload after changes.

Enable `ALIENX_PYTHONANYWHERE='1'` **only behind PythonAnywhere's proxy**. It trusts the documented [`X-Real-IP` header](https://help.pythonanywhere.com/pages/WebAppClientIPAddresses/) for per-client rate limits, not arbitrary `X-Forwarded-For` values. Leave it unset on Render or a directly exposed server, where a client could forge `X-Real-IP`. Other hosting requires its own verified proxy trust configuration.

## Data Maintenance

With no `DATABASE_URL`, local/PythonAnywhere SQLite is auto-created on the first request that needs the database, such as an upload or share lookup, not merely when importing the app or opening the homepage. Without `ALIENX_DATABASE`, the default is `shares.sqlite3` beside `flask_app.py`; use the external absolute path above for PythonAnywhere. PostgreSQL instead requires `flask --app flask_app init-db` with `DATABASE_URL` already set. Switching backends does not migrate existing SQLite shares.

Codes held only in RAM by the previous version cannot migrate automatically. This is a one-time deployment transition: users must create new uploads. Afterward, SQLite-backed shares survive worker restarts and code reloads until their expiry, provided the database is preserved; file availability still depends on Litterbox.

On either backend, expired shares are cleaned in batches of 50 when saving a new share or accessing an expired share. Private Blob objects are deleted before their metadata; failed deletions retain the metadata for retry. Access is denied immediately at expiry, even when deletion is delayed. There is no background cleanup worker. With the same database and storage environment configured, this command runs one batch during idle periods:

```bash
flask --app flask_app cleanup-shares
```

For a backlog, run additional batches or schedule this command. Do not delete private-file metadata with raw SQL, because that loses the object URL needed for cleanup. Upload timeouts or process crashes can leave orphan objects; monitor the dedicated Blob store and reconcile objects without active metadata. A failed database save triggers best-effort deletion of its newly uploaded object. Already downloaded copies cannot be revoked.

Back up SQLite using its backup API/tooling, or stop writes before making a filesystem copy. Keep backups outside static mappings and code replacement, restrict access, and choose a retention policy: backups can retain shared text, metadata, and IP records after live expiry. Deleting rows does not securely erase disk contents or necessarily shrink the SQLite file; monitor disk usage and plan maintenance accordingly. These backups do not contain file payloads hosted by the object store.

SQLite's short write transactions suit a small site, but writes serialize and can contend. Before production use, confirm filesystem locking support and behavior on your PythonAnywhere plan, test expected concurrent load, and monitor database errors. The connection waits up to 10 seconds for locks; database failures can return 503. Sustained write contention calls for a server database, not an assumption that more Web workers remove the limit.

## Access And Privacy

- Five-digit codes are convenient identifiers, **not passwords or encryption**. Anyone who knows or guesses a live code or obtains a link can access the share. Do not upload passwords, credentials, or other sensitive data.
- File bytes pass through the app host, including temporary upload storage, and are sent to Vercel Blob (or Litterbox when no Blob token is configured). Private files are streamed as attachments through the app after expiry checks; the browser never receives the storage token. Shared text is stored directly in the configured database. This is not end-to-end encryption, zero-storage hosting, or a no-logging service; hosting/provider logs and backups may retain information.
- Expiry blocks access through this app; provider retention is separate, and neither expiry nor cancellation can recall downloaded copies. Keep your own backup of anything important. Availability can end before the selected expiry.
- Limits are **10 upload requests per IP per 600 seconds** and **30 lookup requests per IP per 600 seconds**, using separate fixed windows stored in the configured database. Failed requests also count. A valid code-form POST followed by its redirect to the details page counts as **two lookups**; fetching its QR code or clicking the file download link counts as another. Requests beyond the allowance return 429 with `Retry-After`.
- Each file sent from the browser queue consumes one upload request; files rejected locally do not. Users behind a shared NAT/IP share the allowance, and fixed-window limits are not a substitute for authentication or comprehensive abuse protection.
- Some executable/script filename extensions are blocked, but the app does not scan file contents for malware. Treat downloaded files as untrusted.
- QR codes encode the details URL and use the same expiration checks and lookup rate limits. Anyone who scans one can access the share, just like anyone holding its URL.
- Global response headers include `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a Content Security Policy; non-static responses use `Cache-Control: no-store`. These do not make public share codes secret. Never place database credentials or access tokens in public/global headers, share contents, or source files.

## Contributing

Keep changes focused, run the Python tests, and check upload/download behavior in desktop and mobile browsers. Report the configured file limit, hosting plan, HTTP status, and relevant redacted logs when reporting deployment issues; do not include private share contents or live codes.

Created by [Aryan Kahar](https://github.com/aryankahar31).
