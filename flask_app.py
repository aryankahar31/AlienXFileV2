import html as html_mod
import ipaddress
import logging
import os
import re
import secrets
import sqlite3
import time
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import qrcode
import psycopg
import requests
from flask import Flask, Response, g, jsonify, redirect, render_template, request, send_from_directory, url_for
from qrcode.image.svg import SvgPathImage
from psycopg.rows import dict_row
from requests_toolbelt.multipart.encoder import MultipartEncoder
from urllib.parse import urlparse
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

app = Flask(__name__)
SITE_URL = 'https://alienxfilev2.onrender.com/'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000_000  # 1 GB, decimal, plus separate multipart overhead below.
upload_max_bytes = int(os.environ.get('ALIENX_UPLOAD_MAX_BYTES', 95_000_000))
if not 0 < upload_max_bytes <= 95_000_000:
    raise ValueError('ALIENX_UPLOAD_MAX_BYTES must be between 1 and 95000000 for AlienXFile Storage.')
app.config.update(
    DATABASE=os.environ.get('ALIENX_DATABASE', str(Path(__file__).with_name('shares.sqlite3'))),
    DATABASE_URL=os.environ.get('DATABASE_URL'),
    BLOB_READ_WRITE_TOKEN=os.environ.get('BLOB_READ_WRITE_TOKEN', '').strip(),
    INDEXNOW_KEY=os.environ.get('INDEXNOW_KEY', ''),
    UPLOAD_MAX_BYTES=upload_max_bytes,
    LITTERBOX_MAX_BYTES=MAX_FILE_BYTES,
    MAX_CONTENT_LENGTH=MAX_FILE_BYTES + 1_000_000,
    MAX_FORM_MEMORY_SIZE=500_000,
    MAX_FORM_PARTS=20,
    MAX_TEXT_LENGTH=100_000,
    UPLOAD_RATE_LIMIT=30,
    LOOKUP_RATE_LIMIT=30,
    RATE_WINDOW_SECONDS=600,
    LITTERBOX_PROXY_URL=os.environ.get('LITTERBOX_PROXY_URL', ''),
    LITTERBOX_PROXY_SECRET=os.environ.get('LITTERBOX_PROXY_SECRET', ''),
    TRUST_PYTHONANYWHERE_PROXY=os.environ.get('ALIENX_PYTHONANYWHERE') == '1',
    TRUST_RENDER_PROXY=os.environ.get('RENDER') == 'true' and os.environ.get('RENDER_SERVICE_TYPE') == 'web',
)
if os.environ.get('RENDER') == 'true' and not app.config['DATABASE_URL']:
    raise RuntimeError('Set DATABASE_URL to a persistent PostgreSQL database before starting on Render.')
expire_seconds = {'1h': 3600, '12h': 43200, '24h': 86400, '72h': 259200, '168h': 604800}
banned_exts = {'.exe', '.scr', '.cpl', '.jar', '.bat', '.cmd', '.com', '.pif', '.vbs', '.wsf'}
BLOB_API = 'https://vercel.com/api/blob'
SCHEMA = '''
    CREATE TABLE IF NOT EXISTS shares (
        key TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
        content TEXT, url TEXT, size INTEGER NOT NULL, expires DOUBLE PRECISION NOT NULL,
        provider TEXT DEFAULT 'vercel',
        salt TEXT, iv TEXT, is_encrypted INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS shares_expiry ON shares(expires);
    CREATE TABLE IF NOT EXISTS rate_limits (
        ip TEXT NOT NULL, action TEXT NOT NULL, started DOUBLE PRECISION NOT NULL,
        hits INTEGER NOT NULL, PRIMARY KEY (ip, action)
    );
'''
BACKFILL_PROVIDER = '''
    UPDATE shares SET provider = CASE
        WHEN url LIKE 'https://litter.catbox.moe/%' THEN 'litterbox' ELSE 'vercel' END
    WHERE type = 'file' AND provider IS NULL
'''


def get_db():
    if 'db' not in g:
        if app.config['DATABASE_URL']:
            # The provider's pooled URL handles pooling; one connection per request keeps this small.
            g.db = psycopg.connect(app.config['DATABASE_URL'], autocommit=True,
                                   row_factory=dict_row, connect_timeout=10, prepare_threshold=None)
        else:
            g.db = sqlite3.connect(app.config['DATABASE'], timeout=10)
            g.db.row_factory = sqlite3.Row
            g.db.executescript(SCHEMA)
            with g.db:
                g.db.execute('BEGIN IMMEDIATE')
                cols = [column['name'] for column in g.db.execute('PRAGMA table_info(shares)')]
                if 'provider' not in cols:
                    g.db.execute('ALTER TABLE shares ADD COLUMN provider TEXT')
                    g.db.execute(BACKFILL_PROVIDER)
                for col_name, col_type in [('salt', 'TEXT'), ('iv', 'TEXT'), ('is_encrypted', 'INTEGER DEFAULT 0')]:
                    if col_name not in cols:
                        g.db.execute(f'ALTER TABLE shares ADD COLUMN {col_name} {col_type}')
    return g.db


def query(db, sql, parameters=()):
    # Only static application SQL goes here; SQLite and psycopg use different parameter markers.
    return db.execute(sql.replace('?', '%s') if isinstance(db, psycopg.Connection) else sql, parameters)


def transaction(db):
    return db.transaction() if isinstance(db, psycopg.Connection) else db


@app.cli.command('init-db')
def init_db():
    db = get_db()
    if isinstance(db, psycopg.Connection):
        # Run once before Gunicorn workers start, not concurrent DDL on every request.
        with db.transaction():
            db.execute(SCHEMA)
            db.execute('ALTER TABLE shares ADD COLUMN IF NOT EXISTS provider TEXT')
            db.execute(BACKFILL_PROVIDER)
            db.execute("ALTER TABLE shares ALTER COLUMN provider SET DEFAULT 'vercel'")
            db.execute('ALTER TABLE shares ADD COLUMN IF NOT EXISTS salt TEXT')
            db.execute('ALTER TABLE shares ADD COLUMN IF NOT EXISTS iv TEXT')
            db.execute('ALTER TABLE shares ADD COLUMN IF NOT EXISTS is_encrypted INTEGER DEFAULT 0')


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.context_processor
def template_settings():
    limit = app.config['UPLOAD_MAX_BYTES']
    return dict(upload_max_bytes=limit,
                litterbox_max_bytes=app.config['LITTERBOX_MAX_BYTES'],
                site_url=SITE_URL,
                upload_limit_label='1 GB' if limit == MAX_FILE_BYTES else f'{limit / 1_000_000:g} MB',
                max_text_length=app.config['MAX_TEXT_LENGTH'], banned_exts=sorted(banned_exts),
                storage_provider='Vercel Blob and Litterbox')


def blob_headers():
    token = app.config['BLOB_READ_WRITE_TOKEN']
    parts = token.split('_')
    if len(parts) < 5 or parts[:3] != ['vercel', 'blob', 'rw'] or not parts[3].isalnum():
        raise ValueError('Private storage is not configured correctly.')
    return {'Authorization': 'Bearer ' + token, 'x-api-version': '12',
            'x-vercel-blob-store-id': parts[3]}


def checked_blob_url(url):
    host = blob_headers()['x-vercel-blob-store-id'].lower() + '.private.blob.vercel-storage.com'
    if not isinstance(url, str) or not re.fullmatch(
        r'https://' + re.escape(host) + r'/shares/[a-f0-9]{32}/[A-Za-z0-9_.-]+', url
    ):
        raise ValueError('Invalid private storage URL.')
    return url


def delete_blobs(urls):
    with requests.post(BLOB_API + '/delete', headers=blob_headers(),
                       json={'urls': [checked_blob_url(url) for url in urls]},
                       timeout=(10, 30), allow_redirects=False) as response:
        if not 200 <= response.status_code < 300:
            raise requests.HTTPError('Private storage cleanup failed.', response=response)


def cleanup_expired(db):
    # ponytail: request-driven cleanup leaves idle/orphan objects; schedule cleanup and reconcile the store at scale.
    rows = query(db, 'SELECT key, type, url, expires, provider FROM shares WHERE expires <= ? ORDER BY expires LIMIT 50',
                 (time.time(),)).fetchall()
    urls = [row['url'] for row in rows if row['type'] == 'file' and row['provider'] == 'vercel']
    try:
        if urls:
            delete_blobs(urls)
    except (requests.RequestException, ValueError):
        logger.warning('Private storage cleanup deferred; expired shares remain inaccessible.')
        return
    with transaction(db):
        for row in rows:
            query(db, 'DELETE FROM shares WHERE key = ? AND expires = ?', (row['key'], row['expires']))


@app.cli.command('cleanup-shares')
def cleanup_shares():
    cleanup_expired(get_db())


def error_response(message, status):
    if request.path in ('/upload', '/upload-litterbox', '/bulk-download', '/api/url-meta'):
        return jsonify(success=False, uploads=[], errors=[], error=message), status
    return render_template('download.html', error=message), status


@app.before_request
def limit_requests():
    if request.endpoint == 'upload':
        action, limit = 'upload', app.config['UPLOAD_RATE_LIMIT']
    elif request.endpoint in {'download_details', 'download_direct', 'share_qr'} or (
        request.endpoint == 'download_page' and request.method == 'POST'
    ):
        action, limit = 'lookup', app.config['LOOKUP_RATE_LIMIT']
        if request.method == 'POST':
            request.max_content_length = 4096
    else:
        return
    address = request.remote_addr or 'unknown'
    if app.config['TRUST_RENDER_PROXY']:
        # Render's public Cloudflare ingress overwrites this header. Do not trust arbitrary XFF entries.
        address = request.headers.get('CF-Connecting-IP', '')
    elif app.config['TRUST_PYTHONANYWHERE_PROXY']:
        # PythonAnywhere sets X-Real-IP. Never enable this on a directly exposed server.
        address = request.headers.get('X-Real-IP', address)
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        address = 'unknown'
    now = time.time()
    window = app.config['RATE_WINDOW_SECONDS']
    db = get_db()
    # ponytail: per-IP fixed windows allow boundary bursts/shared-IP contention; use a gateway limiter at scale.
    with transaction(db):
        query(db, 'DELETE FROM rate_limits WHERE started <= ?', (now - window,))
        query(db, '''INSERT INTO rate_limits VALUES (?, ?, ?, 1)
                      ON CONFLICT(ip, action) DO UPDATE SET hits = rate_limits.hits + 1''',
                   (address, action, now))
        row = query(db, 'SELECT hits, started FROM rate_limits WHERE ip = ? AND action = ?',
                         (address, action)).fetchone()
    if row['hits'] > limit:
        retry = max(1, int(row['started'] + window - now) + 1)
        body, status = error_response(f'Too many requests. Try again in {retry} seconds.', 429)
        return body, status, {'Retry-After': str(retry)}


@app.after_request
def response_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "connect-src 'self' https://alienxfile-proxy.fly.dev; "
        "img-src 'self' data: https://litter.catbox.moe; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.endpoint != 'static':
        response.headers['Cache-Control'] = 'no-store'
    # Let crawlers read noindex; robots.txt must not block these private routes.
    if request.endpoint not in {'index', 'robots', 'sitemap', 'static'} or response.status_code >= 400:
        response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    return response


def share_details(row):
    result = dict(key=row['key'], type=row['type'], name=row['name'], content=row['content'],
                storageProvider=row['provider'] if row['type'] == 'file' else None,
                size=row['size'], expires=datetime.fromtimestamp(row['expires'], timezone.utc).isoformat(),
                page_url=url_for('download_details', key=row['key'], _external=True),
                link=url_for('download_direct', key=row['key'], _external=True))
    is_enc = row['is_encrypted'] if 'is_encrypted' in row.keys() else 0
    if is_enc:
        result['is_encrypted'] = True
        result['salt'] = row['salt']
        result['iv'] = row['iv']
        if row['type'] == 'text':
            result['encrypted_content'] = row['content']
        else:
            result['encrypted_url'] = row['url']
    else:
        result['is_encrypted'] = False
    return result


def save_share(kind, name, size, expires, content=None, url=None, provider=None,
               custom_key=None, salt=None, iv=None, is_encrypted=False):
    db = get_db()
    cleanup_expired(db)
    with transaction(db):
        for _ in range(100):
            key = custom_key if custom_key else f'{secrets.randbelow(100_000):05d}'
            inserted = query(db, '''INSERT INTO shares (key, type, name, content, url, size, expires, provider,
                                                        salt, iv, is_encrypted)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                     ON CONFLICT(key) DO NOTHING''',
                              (key, kind, name, content, url, size, expires, provider,
                               salt, iv, 1 if is_encrypted else 0))
            if inserted.rowcount:
                break
            if custom_key:
                return None
        else:
            raise ValueError('No share code available. Try again later.')
    row = query(db, 'SELECT * FROM shares WHERE key = ?', (key,)).fetchone()
    details = share_details(row)
    details.pop('content')
    return details


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/robots.txt')
def robots():
    return Response(f'User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}sitemap.xml\n', mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    return Response('<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    f'<url><loc>{SITE_URL}</loc></url></urlset>', mimetype='application/xml')


@app.route('/indexnow-key.txt')
def indexnow_key():
    key = app.config['INDEXNOW_KEY']
    return Response(key, status=200 if key else 404, mimetype='text/plain')


@app.route('/googled943441d68fdfc65.html')
def google_site_verification():
    return send_from_directory(app.root_path, 'googled943441d68fdfc65.html')


@app.route('/download', methods=['GET', 'POST'])
def download_page():
    if request.method == 'POST':
        key = request.form.get('key', '').strip()
        if not re.fullmatch(r'[0-9]{5}', key):
            return render_template('download.html', key=key, error='Please enter a 5-digit code.'), 400
        return redirect(url_for('download_details', key=key), code=303)
    return render_template('download.html')


@app.route('/upload', methods=['POST'])
def upload():
    mode = request.form.get('mode', 'file')
    expiry = request.form.get('expire', '1h')
    custom_key = request.form.get('customKey', '').strip() or None
    if custom_key and not re.fullmatch(r'[0-9]{5}', custom_key):
        return error_response('Custom code must be exactly 5 digits.', 400)
    is_encrypted = request.form.get('isEncrypted') == '1'
    salt = request.form.get('salt') or None
    iv_val = request.form.get('iv') or None
    if is_encrypted and (not salt or not iv_val):
        return error_response('Encryption parameters missing.', 400)
    if mode not in {'file', 'text'} or expiry not in expire_seconds:
        return error_response('Choose a valid share mode and expiration.', 400)
    if mode == 'text':
        text = request.form.get('text', '').replace('\r\n', '\n').strip()
        if '\x00' in text:
            return error_response('Text cannot contain null characters.', 400)
        if not text or len(text) > app.config['MAX_TEXT_LENGTH']:
            return error_response(f'Enter text between 1 and {app.config["MAX_TEXT_LENGTH"]} characters.', 400)
        try:
            shared = save_share('text', 'Shared Text', len(text.encode('utf-8')),
                                time.time() + expire_seconds[expiry], content=text,
                                custom_key=custom_key, salt=salt, iv=iv_val, is_encrypted=is_encrypted)
            if shared is None:
                return error_response('That custom code is already taken.', 409)
        except ValueError as exc:
            return error_response(str(exc), 503)
        return jsonify(success=True, uploads=[shared], errors=[])

    provider = request.form.get('storageProvider', 'vercel')
    if provider not in {'vercel', 'litterbox'}:
        return error_response('Choose AlienXFile Storage or Litterbox Large Files.', 400)
    files = request.files.getlist('file')
    if not files or len(files) > 10:
        return error_response('Select between 1 and 10 files per request.', 400)
    if provider == 'vercel' and not app.config['BLOB_READ_WRITE_TOKEN']:
        return error_response('AlienXFile Storage is temporarily unavailable. Please try again later.', 503)
    limit = app.config['UPLOAD_MAX_BYTES'] if provider == 'vercel' else min(app.config['LITTERBOX_MAX_BYTES'], MAX_FILE_BYTES)
    uploads, errors = [], []
    for file in files:
        filename = secure_filename(file.filename or '')
        if not filename or len(filename) > 255:
            errors.append('A file has an empty or overly long filename.')
            continue
        if Path(filename).suffix.lower() in banned_exts:
            errors.append(f'{filename}: This file extension is blocked.')
            continue
        stored_blob = None
        try:
            file.stream.seek(0, 2)
            size = file.stream.tell()
            file.stream.seek(0)
            if size > limit:
                message = (f"This file exceeds AlienXFile Storage's {template_settings()['upload_limit_label']} limit. "
                           'Choose Litterbox Large Files to upload it.' if provider == 'vercel'
                           else "This file exceeds Litterbox's 1 GB limit.")
                errors.append(f'{filename}: {message}')
                continue
            expires = time.time() + expire_seconds[expiry]
            if provider == 'vercel':
                with requests.put(BLOB_API + '/',
                                  params={'pathname': f'shares/{secrets.token_hex(16)}/{filename}'},
                                  data=file.stream if size else b'', headers={
                                      **blob_headers(), 'Content-Length': str(size),
                                      'Content-Type': 'application/octet-stream',
                                      'x-content-type': 'application/octet-stream',
                                      'x-vercel-blob-access': 'private', 'x-add-random-suffix': '0',
                                      'x-allow-overwrite': '0', 'x-cache-control-max-age': '60',
                                  }, timeout=(10, 180), allow_redirects=False) as response:
                    response.raise_for_status()
                    result = response.json()
                    if not 200 <= response.status_code < 300 or not isinstance(result, dict):
                        raise ValueError('Invalid private storage response.')
                    stored_blob = link = checked_blob_url(result.get('url'))
            else:
                proxy_url = app.config.get('LITTERBOX_PROXY_URL', '')
                proxy_secret = app.config.get('LITTERBOX_PROXY_SECRET', '')
                if proxy_url:
                    # Route through PythonAnywhere proxy (Render's IP is blocked by Litterbox).
                    body = MultipartEncoder(fields={
                        'time': expiry,
                        'fileToUpload': (filename, file.stream, 'application/octet-stream'),
                    })
                    with requests.post(
                        proxy_url.rstrip('/') + '/proxy/litterbox', data=body,
                        headers={'Content-Type': body.content_type,
                                 'X-Proxy-Secret': proxy_secret},
                        timeout=(10, 180), allow_redirects=False,
                    ) as response:
                        if response.status_code != 200:
                            raise ValueError(f'Proxy error (HTTP {response.status_code}).')
                        result = response.json()
                        link = result.get('url', '')
                else:
                    # Direct upload (may fail from Render — use proxy instead).
                    body = MultipartEncoder(fields={
                        'reqtype': 'fileupload', 'time': expiry,
                        'fileToUpload': (filename, file.stream, 'application/octet-stream'),
                    })
                    with requests.post(
                        'https://litterbox.catbox.moe/resources/internals/api.php', data=body,
                        headers={'Content-Type': body.content_type}, timeout=(10, 180), allow_redirects=False,
                    ) as response:
                        response.raise_for_status()
                        link = response.text.strip()
                if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link):
                    raise ValueError('Storage provider returned an invalid file link.')
            uploads.append(save_share('file', filename, size, expires, url=link, provider=provider,
                                      custom_key=custom_key, salt=salt, iv=iv_val, is_encrypted=is_encrypted))
            if custom_key and uploads[-1] is None:
                errors.append(f'{filename}: That custom code is already taken.')
                uploads.pop()
        except (requests.RequestException, ValueError, OSError, sqlite3.Error, psycopg.Error) as exc:
            if stored_blob:
                try:
                    delete_blobs([stored_blob])
                except (requests.RequestException, ValueError):
                    logger.warning('An unregistered private upload needs storage cleanup.')
            status = getattr(getattr(exc, 'response', None), 'status_code', None)
            logger.warning('Upload failed (provider=%s; %s; upstream status=%s)', provider, type(exc).__name__, status)
            message = 'Upload could not be completed. The storage provider or server may be unavailable.'
            if provider == 'litterbox':
                if isinstance(exc, requests.Timeout):
                    message = 'Litterbox upload timed out. Please try again later.'
                elif status:
                    message = f'Litterbox rejected the server upload (HTTP {status}). Please try again later or use AlienXFile Storage for smaller files.'
                elif isinstance(exc, requests.RequestException):
                    message = 'Could not reach Litterbox. Please try again later.'
                else:
                    message = 'The Litterbox upload could not be completed. Please try again later.'
            errors.append(f'{filename}: {message}')
    return jsonify(success=bool(uploads), uploads=uploads, errors=errors), 200 if uploads else 400


@app.route('/upload-litterbox', methods=['POST'])
def upload_litterbox():
    """Accept a pre-uploaded Litterbox URL from the browser (direct upload path)."""
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    name = (data.get('name') or '').strip()[:255]
    size = data.get('size', 0)
    expire = data.get('expire', '1h')
    custom_key = (data.get('customKey') or '').strip() or None
    is_encrypted = data.get('isEncrypted') is True or data.get('isEncrypted') == '1'
    salt = data.get('salt') or None
    iv_val = data.get('iv') or None
    if custom_key and not re.fullmatch(r'[0-9]{5}', custom_key):
        return error_response('Custom code must be exactly 5 digits.', 400)
    if expire not in expire_seconds:
        return error_response('Choose a valid share mode and expiration.', 400)
    if not name:
        name = 'Shared File'
    if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', url):
        return error_response('Invalid Litterbox URL.', 400)
    if not isinstance(size, (int, float)) or size < 0 or size > MAX_FILE_BYTES:
        return error_response('Invalid file size.', 400)
    if Path(name).suffix.lower() in banned_exts:
        return error_response(f'{name}: This file extension is blocked.', 400)
    try:
        shared = save_share('file', name, int(size), time.time() + expire_seconds[expire],
                            url=url, provider='litterbox', custom_key=custom_key,
                            salt=salt, iv=iv_val, is_encrypted=is_encrypted)
        if shared is None:
            return error_response('That custom code is already taken.', 409)
    except ValueError as exc:
        return error_response(str(exc), 503)
    return jsonify(success=True, uploads=[shared], errors=[])


@app.route('/qr/<key>', endpoint='share_qr')
@app.route('/share/<key>', endpoint='download_details')
@app.route('/download/<key>', endpoint='download_direct')
def download_share(key):
    if not re.fullmatch(r'[0-9]{5}', key):
        return error_response('Invalid or expired code. Enter a 5-digit code below.', 404)
    db = get_db()
    row = query(db, 'SELECT * FROM shares WHERE key = ?', (key,)).fetchone()
    if row is None:
        return error_response('Invalid or expired code. Check the code or ask for a new share.', 404)
    if row['expires'] <= time.time():
        cleanup_expired(db)
        return error_response('This share has expired. Ask the sender to upload it again.', 410)
    if request.endpoint == 'download_direct' and row['type'] == 'file':
        if row['provider'] == 'litterbox':
            if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', row['url'] or ''):
                return error_response('This file has an invalid storage link. Ask the sender to share it again.', 502)
            return redirect(row['url'])
        if row['provider'] != 'vercel':
            return error_response('This file has an unknown storage provider. Ask the sender to share it again.', 502)
        try:
            upstream = requests.get(checked_blob_url(row['url']),
                                    headers={'Authorization': blob_headers()['Authorization'], 'Accept-Encoding': 'identity'},
                                    stream=True, timeout=(10, 60), allow_redirects=False)
        except (requests.RequestException, ValueError):
            return error_response('File storage is temporarily unavailable. Please try again.', 502)
        if upstream.status_code != 200:
            upstream.close()
            return error_response('This file is unavailable from storage. Ask the sender to share it again.', 502)
        response = Response(upstream.iter_content(chunk_size=64 * 1024), content_type='application/octet-stream')
        response.headers.set('Content-Disposition', 'attachment', filename=secure_filename(row['name']) or 'download')
        response.headers['Content-Length'] = str(row['size'])
        response.call_on_close(upstream.close)
        return response
    if request.endpoint == 'share_qr':
        image = qrcode.make(url_for('download_details', key=key, _external=True), image_factory=SvgPathImage)
        output = BytesIO()
        image.save(output)
        return Response(output.getvalue(), mimetype='image/svg+xml')
    return render_template('download.html', share=share_details(row))


@app.route('/bulk-download', methods=['POST'])
def bulk_download():
    data = request.get_json(silent=True) or {}
    keys = data.get('keys', [])
    if not keys or not isinstance(keys, list) or len(keys) > 10:
        return jsonify(error='Provide 1-10 share keys.'), 400
    db = get_db()
    zip_buf = BytesIO()
    found = 0
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for key in keys:
            if not isinstance(key, str) or not re.fullmatch(r'[0-9]{5}', key):
                continue
            row = query(db, 'SELECT * FROM shares WHERE key = ?', (key,)).fetchone()
            if not row or row['type'] != 'file' or row['expires'] <= time.time():
                continue
            try:
                if row['provider'] == 'litterbox':
                    resp = requests.get(row['url'], timeout=(10, 60))
                    if resp.status_code == 200:
                        zf.writestr(row['name'], resp.content)
                        found += 1
                elif row['provider'] == 'vercel':
                    resp = requests.get(row['url'],
                                        headers={'Authorization': blob_headers()['Authorization'], 'Accept-Encoding': 'identity'},
                                        timeout=(10, 60))
                    if resp.status_code == 200:
                        zf.writestr(row['name'], resp.content)
                        found += 1
            except (requests.RequestException, ValueError):
                continue
    if not found:
        return jsonify(error='No valid files found for the provided codes.'), 404
    zip_buf.seek(0)
    return Response(zip_buf.getvalue(), mimetype='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="alienxfile-{found}-files.zip"'})


@app.route('/api/url-meta', methods=['POST'])
def url_meta():
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url or not url.startswith(('http://', 'https://')):
        return jsonify(error='Provide a valid URL.'), 400
    try:
        parsed = urlparse(url)
        resp = requests.get(url, timeout=(5, 10), headers={
            'User-Agent': 'Mozilla/5.0 (compatible; AlienXFile/2.0)',
            'Accept': 'text/html',
        }, allow_redirects=True)
        if resp.status_code != 200:
            return jsonify(error=f'Could not fetch URL (HTTP {resp.status_code}).'), 402
        body = resp.text[:100_000]
        title = ''
        desc = ''
        for pattern, attr in [
            (r'<title[^>]*>(.*?)</title>', 'title'),
            (r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)', 'og_title'),
            (r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:title', 'og_title2'),
            (r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)', 'desc'),
            (r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)', 'og_desc'),
            (r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:description', 'og_desc2'),
        ]:
            m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if m:
                val = html_mod.unescape(m.group(1).strip())
                if attr == 'title' and not title:
                    title = val[:200]
                elif attr.startswith('og_title') and not title:
                    title = val[:200]
                elif attr == 'desc' and not desc:
                    desc = val[:500]
                elif attr.startswith('og_desc') and not desc:
                    desc = val[:500]
        if not title:
            title = parsed.netloc or url[:100]
        return jsonify(title=title, description=desc, url=url)
    except (requests.RequestException, ValueError):
        return jsonify(error='Could not fetch URL metadata.'), 502


@app.errorhandler(HTTPException)
def http_error(exc):
    messages = {400: 'The request could not be read. Please try again.',
                404: 'Page not found. Enter a share code below.',
                405: 'This request method is not supported.',
                413: (f'Upload too large. AlienXFile Storage allows up to {template_settings()["upload_limit_label"]} per file; Litterbox up to 1 GB. Hosting limits may be lower.'
                      if request.path == '/upload' else 'The submitted code is too long. Enter a 5-digit code.'),
                500: 'Something went wrong. Please try again later.'}
    body, status = error_response(messages.get(exc.code, exc.description), exc.code)
    response = app.make_response((body, status))
    for name, value in exc.get_headers():
        if name.lower() != 'content-type':
            response.headers[name] = value
    return response


@app.errorhandler(sqlite3.Error)
@app.errorhandler(psycopg.Error)
def database_error(exc):
    logger.error('Share database unavailable (%s)', type(exc).__name__)
    return error_response('Share storage is temporarily unavailable. Please try again later.', 503)
