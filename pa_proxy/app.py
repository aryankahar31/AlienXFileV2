"""AlienXFile V2 — Litterbox proxy for PythonAnywhere.

Two endpoints:
  POST /proxy/litterbox  — Authenticated, for Render server-side uploads.
  POST /upload           — Public (CORS), for direct browser uploads to Litterbox.
"""

import os
import re
from io import BytesIO

import requests
from flask import Flask, jsonify, request
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = Flask(__name__)

PROXY_SECRET = os.environ.get('LITTERBOX_PROXY_SECRET', '')
LITTERBOX_URL = 'https://litterbox.catbox.moe/resources/internals/api.php'
ALLOWED_ORIGINS = {'https://alienxfilev2.onrender.com', 'http://localhost:5000', 'http://127.0.0.1:5000'}


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
        files={'fileToUpload': (file.filename, BytesIO(file.read()))},
        headers={'User-Agent': 'curl/8.5.0'},
        timeout=(30, 300),
    )
    link = response.text.strip()
    if not link.startswith('https://'):
        raise ValueError(f'Invalid API response: {link[:100]}')
    if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link):
        raise ValueError(f'Invalid Litterbox URL: {link[:100]}')
    return link


def _cors_headers():
    origin = request.headers.get('Origin', '')
    headers = {'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, X-Proxy-Secret'}
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


@app.route('/proxy/litterbox', methods=['POST', 'OPTIONS'])
def proxy_upload():
    if request.method == 'OPTIONS':
        return '', 204, _cors_headers()
    auth = request.headers.get('X-Proxy-Secret', '')
    if not PROXY_SECRET or auth != PROXY_SECRET:
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
    if request.method == 'OPTIONS':
        return '', 204, _cors_headers()
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


@app.route('/health')
def health():
    return jsonify(status='ok'), 200
