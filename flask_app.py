import ipaddress
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import qrcode
import psycopg
import requests
from flask import Flask, Response, g, jsonify, redirect, render_template, request, url_for
from qrcode.image.svg import SvgPathImage
from psycopg.rows import dict_row
from requests_toolbelt.multipart.encoder import MultipartEncoder
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

app = Flask(__name__)
SITE_URL = 'https://alienxfilev2.onrender.com/'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000_000  # 1 GB, decimal, plus separate multipart overhead below.
upload_max_bytes = int(os.environ.get('ALIENX_UPLOAD_MAX_BYTES', MAX_FILE_BYTES))
if not 0 < upload_max_bytes <= MAX_FILE_BYTES:
    raise ValueError('ALIENX_UPLOAD_MAX_BYTES must be between 1 and 1000000000.')
app.config.update(
    DATABASE=os.environ.get('ALIENX_DATABASE', str(Path(__file__).with_name('shares.sqlite3'))),
    DATABASE_URL=os.environ.get('DATABASE_URL'),
    BLOB_READ_WRITE_TOKEN=os.environ.get('BLOB_READ_WRITE_TOKEN', '').strip(),
    INDEXNOW_KEY=os.environ.get('INDEXNOW_KEY', ''),
    UPLOAD_MAX_BYTES=upload_max_bytes,
    MAX_CONTENT_LENGTH=upload_max_bytes + 1_000_000,
    MAX_FORM_MEMORY_SIZE=500_000,
    MAX_FORM_PARTS=20,
    MAX_TEXT_LENGTH=100_000,
    UPLOAD_RATE_LIMIT=10,
    LOOKUP_RATE_LIMIT=30,
    RATE_WINDOW_SECONDS=600,
    TRUST_PYTHONANYWHERE_PROXY=os.environ.get('ALIENX_PYTHONANYWHERE') == '1',
    TRUST_RENDER_PROXY=os.environ.get('RENDER') == 'true' and os.environ.get('RENDER_SERVICE_TYPE') == 'web',
)
if os.environ.get('RENDER') == 'true' and not app.config['DATABASE_URL']:
    raise RuntimeError('Set DATABASE_URL to a persistent PostgreSQL database before starting on Render.')
expire_seconds = {'1h': 3600, '12h': 43200, '24h': 86400, '72h': 259200}
banned_exts = {'.exe', '.scr', '.cpl', '.jar', '.bat', '.cmd', '.com', '.pif', '.vbs', '.wsf'}
BLOB_API = 'https://vercel.com/api/blob'
SCHEMA = '''
    CREATE TABLE IF NOT EXISTS shares (
        key TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
        content TEXT, url TEXT, size INTEGER NOT NULL, expires DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS shares_expiry ON shares(expires);
    CREATE TABLE IF NOT EXISTS rate_limits (
        ip TEXT NOT NULL, action TEXT NOT NULL, started DOUBLE PRECISION NOT NULL,
        hits INTEGER NOT NULL, PRIMARY KEY (ip, action)
    );
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


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.context_processor
def template_settings():
    limit = app.config['UPLOAD_MAX_BYTES']
    return dict(upload_max_bytes=limit,
                site_url=SITE_URL,
                upload_limit_label='1 GB' if limit == MAX_FILE_BYTES else f'{limit / 1_000_000:g} MB',
                max_text_length=app.config['MAX_TEXT_LENGTH'], banned_exts=sorted(banned_exts),
                storage_provider='Vercel Blob' if app.config['BLOB_READ_WRITE_TOKEN'] else 'Litterbox')


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
    rows = query(db, 'SELECT key, type, url, expires FROM shares WHERE expires <= ? ORDER BY expires LIMIT 50',
                 (time.time(),)).fetchall()
    urls = [row['url'] for row in rows if row['type'] == 'file'
            and not (row['url'] or '').startswith('https://litter.catbox.moe/')]
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
    if request.path == '/upload':
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
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.endpoint != 'static':
        response.headers['Cache-Control'] = 'no-store'
    # Let crawlers read noindex; robots.txt must not block these private routes.
    if request.endpoint not in {'index', 'robots', 'sitemap', 'static'} or response.status_code >= 400:
        response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    return response


def share_details(row):
    return dict(key=row['key'], type=row['type'], name=row['name'], content=row['content'],
                size=row['size'], expires=datetime.fromtimestamp(row['expires'], timezone.utc).isoformat(),
                page_url=url_for('download_details', key=row['key'], _external=True),
                link=url_for('download_direct', key=row['key'], _external=True))


def save_share(kind, name, size, expires, content=None, url=None):
    db = get_db()
    cleanup_expired(db)
    with transaction(db):
        for _ in range(100):
            key = f'{secrets.randbelow(100_000):05d}'
            inserted = query(db, '''INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?, ?)
                                    ON CONFLICT(key) DO NOTHING''',
                             (key, kind, name, content, url, size, expires))
            if inserted.rowcount:
                break
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
                                time.time() + expire_seconds[expiry], content=text)
        except ValueError as exc:
            return error_response(str(exc), 503)
        return jsonify(success=True, uploads=[shared], errors=[])

    files = request.files.getlist('file')
    if not files or len(files) > 10:
        return error_response('Select between 1 and 10 files per request.', 400)
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
            if size > app.config['UPLOAD_MAX_BYTES']:
                errors.append(f'{filename}: File exceeds the {template_settings()["upload_limit_label"]} limit.')
                continue
            expires = time.time() + expire_seconds[expiry]
            if app.config['BLOB_READ_WRITE_TOKEN']:
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
                # Stream the temporary file; requests' files= would buffer the full multipart body.
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
                    if response.status_code != 200 or not re.fullmatch(
                        r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link
                    ):
                        raise ValueError('Storage provider returned an invalid file link.')
            uploads.append(save_share('file', filename, size, expires, url=link))
        except (requests.RequestException, ValueError, OSError, sqlite3.Error, psycopg.Error) as exc:
            if stored_blob:
                try:
                    delete_blobs([stored_blob])
                except (requests.RequestException, ValueError):
                    logger.warning('An unregistered private upload needs storage cleanup.')
            logger.warning('Upload failed (%s; upstream status=%s)', type(exc).__name__,
                           getattr(getattr(exc, 'response', None), 'status_code', None))
            errors.append(f'{filename}: Upload could not be completed. The storage provider or server may be unavailable.')
    return jsonify(success=bool(uploads), uploads=uploads, errors=errors), 200 if uploads else 400


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
        if (row['url'] or '').startswith('https://litter.catbox.moe/'):
            return redirect(row['url'])
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


@app.errorhandler(HTTPException)
def http_error(exc):
    messages = {400: 'The request could not be read. Please try again.',
                404: 'Page not found. Enter a share code below.',
                405: 'This request method is not supported.',
                413: (f'Upload too large. Send one file per request, up to {app.config["UPLOAD_MAX_BYTES"]:,} bytes. Hosting limits may be lower.'
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
