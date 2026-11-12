"""AlienXFile V2 — Litterbox proxy for large, direct browser uploads.

Three endpoints:
  POST /proxy/litterbox — server-to-server (Render), authenticated with the
                           shared secret in the X-Proxy-Secret header.
  POST /upload          — direct browser uploads, authenticated with a signed,
                           single-use X-Upload-Ticket minted by AlienXFileV2.
  GET  /health          — liveness probe.

The proxy refuses to start without a real LITTERBOX_PROXY_SECRET: a missing,
short or placeholder secret would otherwise leave /upload open to anyone.
"""

import hmac
import os
import re
import threading
import time

import requests
from flask import Flask, jsonify, request
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:  # imported as part of the pa_proxy package (repository root)
    from .tickets import MAX_TICKET_TTL_SECONDS, verify_ticket
except ImportError:  # imported as a top-level module (Docker / PythonAnywhere)
    from tickets import MAX_TICKET_TTL_SECONDS, verify_ticket

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024

LITTERBOX_URL = 'https://litterbox.catbox.moe/resources/internals/api.php'
ALLOWED_ORIGINS = {'https://alienxfilev2.onrender.com', 'https://alienxfile-proxy.fly.dev', 'http://localhost:5000', 'http://127.0.0.1:5000'}
PLACEHOLDER_SECRETS = {'CHANGE_ME_TO_A_RANDOM_SECRET', 'CHANGE_ME', 'REPLACE_ME', 'SECRET'}
MIN_SECRET_LENGTH = 24


def _load_proxy_secret() -> str:
    """Read the shared secret or refuse to start.

    Startup validation is the only reliable way to keep the deployment from
    running with a guessable or placeholder credential.
    """
    secret = (os.environ.get('LITTERBOX_PROXY_SECRET') or '').strip()
    if not secret:
        raise RuntimeError('LITTERBOX_PROXY_SECRET is not set; refusing to start.')
    if secret.upper() in PLACEHOLDER_SECRETS:
        raise RuntimeError('LITTERBOX_PROXY_SECRET is a placeholder value; refusing to start.')
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f'LITTERBOX_PROXY_SECRET is shorter than {MIN_SECRET_LENGTH} characters; refusing to start.')
    return secret


PROXY_SECRET = _load_proxy_secret()

MAX_UPLOAD_BYTES = int(os.environ.get('PROXY_MAX_UPLOAD_BYTES', str(1 * 1024 * 1024 * 1024)))
UPLOAD_RATE_LIMIT = int(os.environ.get('PROXY_UPLOAD_RATE_LIMIT', '30'))
UPLOAD_RATE_WINDOW = int(os.environ.get('PROXY_UPLOAD_RATE_WINDOW', '3600'))
SERVER_RATE_LIMIT = int(os.environ.get('PROXY_SERVER_RATE_LIMIT', '600'))
SERVER_RATE_WINDOW = int(os.environ.get('PROXY_SERVER_RATE_WINDOW', '3600'))
MAX_TICKET_TTL = int(os.environ.get('PROXY_MAX_TICKET_TTL', str(MAX_TICKET_TTL_SECONDS)))


class _FixedWindowLimiter:
    """Small in-memory fixed-window limiter (the proxy keeps no database)."""

    def __init__(self, limit, window):
        self.limit = max(0, int(limit))
        self.window = max(1, int(window))
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key):
        """Return (allowed, retry_after_seconds)."""
        now = time.time()
        with self._lock:
            if len(self._hits) > 4096:
                stale = [k for k, (count, started) in self._hits.items()
                         if started <= now - self.window]
                for k in stale:
                    self._hits.pop(k, None)
            count, started = self._hits.get(key, (0, now))
            if started <= now - self.window:
                count, started = 0, now
            if count >= self.limit:
                return False, max(1, int(started + self.window - now) + 1)
            self._hits[key] = (count + 1, started)
            return True, 0


class _NonceStore:
    """Single-use ticket nonces, expired lazily."""

    def __init__(self):
        self._seen = {}
        self._lock = threading.Lock()

    def consume(self, nonce, expires_at):
        """Return True when the nonce is used for the first time."""
        now = time.time()
        with self._lock:
            if len(self._seen) > 8192:
                for key, expiry in list(self._seen.items()):
                    if expiry <= now:
                        self._seen.pop(key, None)
            if nonce in self._seen:
                return False
            self._seen[nonce] = float(expires_at)
            return True


UPLOAD_LIMITER = _FixedWindowLimiter(UPLOAD_RATE_LIMIT, UPLOAD_RATE_WINDOW)
SERVER_LIMITER = _FixedWindowLimiter(SERVER_RATE_LIMIT, SERVER_RATE_WINDOW)
NONCES = _NonceStore()


def create_session():
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["POST"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _upload_to_litterbox(file, expiry):
    session = create_session()
    response = session.post(
        LITTERBOX_URL,
        data={'reqtype': 'fileupload', 'time': expiry},
        files={'fileToUpload': (file.filename, file.read())},
        headers={'User-Agent': 'curl/8.5.0'},
        timeout=(60, 600),
    )
    link = response.text.strip()
    if not link.startswith('https://'):
        raise ValueError(f'Invalid API response: {link[:100]}')
    if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link):
        raise ValueError(f'Invalid Litterbox URL: {link[:100]}')
    return link


def _client_ip():
    """Best-effort client address for rate limiting."""
    fly_ip = (request.headers.get('Fly-Client-IP') or '').strip()
    if fly_ip:
        return fly_ip
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        parts = [part.strip() for part in forwarded.split(',') if part.strip()]
        if parts:
            return parts[-1]
    return request.remote_addr or 'unknown'


def _cors_headers():
    origin = request.headers.get('Origin', '')
    headers = {'Access-Control-Allow-Methods': 'POST, OPTIONS',
               'Access-Control-Allow-Headers': 'Content-Type, X-Proxy-Secret, X-Upload-Ticket'}
    if origin in ALLOWED_ORIGINS:
        headers['Access-Control-Allow-Origin'] = origin
        headers['Access-Control-Allow-Credentials'] = 'true'
    return headers


@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin', '')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


def _secret_matches(candidate):
    """Constant-time comparison of the shared proxy secret."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode('utf-8'), PROXY_SECRET.encode('utf-8'))


@app.route('/proxy/litterbox', methods=['POST', 'OPTIONS'])
def proxy_upload():
    if request.method == 'OPTIONS':
        return '', 204, _cors_headers()
    allowed, retry_after = SERVER_LIMITER.allow(_client_ip())
    if not allowed:
        return jsonify(error='Too many proxy uploads. Try again later.'), 429, {'Retry-After': str(retry_after)}
    if not _secret_matches(request.headers.get('X-Proxy-Secret', '')):
        return jsonify(error='Forbidden.'), 403
    expiry = request.form.get('time', '1h')
    if expiry not in {'1h', '12h', '24h', '72h'}:
        return jsonify(error='Invalid expiry.'), 400
    file = request.files.get('fileToUpload')
    if not file or not file.filename:
        return jsonify(error='No file provided.'), 400
    try:
        link = _upload_to_litterbox(file, expiry)
    except requests.Timeout:
        return jsonify(error='Litterbox upload timed out.'), 504
    except requests.RequestException as exc:
        return jsonify(error=f'Could not reach Litterbox: {exc}'), 502
    except ValueError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify(url=link), 200


@app.route('/upload', methods=['POST', 'OPTIONS'])
def direct_upload():
    """Browser uploads: authorised by a signed, single-use ticket.

    The shared secret never reaches the browser, so a ticket minted by
    AlienXFileV2 is required instead of an unauthenticated request.
    """
    if request.method == 'OPTIONS':
        return '', 204, _cors_headers()
    allowed, retry_after = UPLOAD_LIMITER.allow(_client_ip())
    if not allowed:
        return jsonify(error='Too many uploads. Try again later.'), 429, {'Retry-After': str(retry_after)}
    ticket = request.headers.get('X-Upload-Ticket', '')
    try:
        claims = verify_ticket(PROXY_SECRET, ticket, max_size=MAX_UPLOAD_BYTES, max_ttl=MAX_TICKET_TTL)
    except ValueError as exc:
        # The reason code is safe to log; the ticket itself never is.
        app.logger.warning('Upload ticket rejected (%s)', exc)
        return jsonify(error='Upload authorization failed.'), 403
    if not NONCES.consume(claims['nonce'], claims['expires_at']):
        app.logger.warning('Upload ticket replay rejected')
        return jsonify(error='Upload authorization has already been used.'), 403
    declared = claims['size']
    if request.content_length and request.content_length > declared + 64 * 1024:
        return jsonify(error='Upload authorization does not cover this file.'), 403
    expiry = request.form.get('time', '1h')
    if expiry not in {'1h', '12h', '24h', '72h'}:
        return jsonify(error='Invalid expiry.'), 400
    file = request.files.get('fileToUpload')
    if not file or not file.filename:
        return jsonify(error='No file provided.'), 400
    payload = file.read()
    if len(payload) > declared or len(payload) > MAX_UPLOAD_BYTES:
        return jsonify(error='Upload authorization does not cover this file.'), 403
    try:
        session = create_session()
        response = session.post(
            LITTERBOX_URL,
            data={'reqtype': 'fileupload', 'time': expiry},
            files={'fileToUpload': (file.filename, payload)},
            headers={'User-Agent': 'curl/8.5.0'},
            timeout=(60, 600),
        )
        link = response.text.strip()
        if not link.startswith('https://'):
            raise ValueError(f'Invalid API response: {link[:100]}')
        if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link):
            raise ValueError(f'Invalid Litterbox URL: {link[:100]}')
    except requests.Timeout:
        return jsonify(error='Litterbox upload timed out.'), 504
    except requests.RequestException as exc:
        return jsonify(error=f'Could not reach Litterbox: {exc}'), 502
    except ValueError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify(url=link), 200


@app.route('/health')
def health():
    return jsonify(status='ok'), 200
