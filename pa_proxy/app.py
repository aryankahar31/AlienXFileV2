"""AlienXFile V2 — Litterbox proxy for PythonAnywhere.

This small Flask app accepts file uploads from Render and forwards them to
Litterbox (litterbox.catbox.moe), bypassing Render's blocked IP range.

Shared-secret authentication prevents external abuse.
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


def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["POST"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


@app.route('/proxy/litterbox', methods=['POST'])
def proxy_upload():
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
        session = create_session()
        response = session.post(
            LITTERBOX_URL,
            data={'reqtype': 'fileupload', 'time': expiry},
            files={'fileToUpload': (file.filename, BytesIO(file.read()))},
            headers={'User-Agent': 'curl/8.5.0'},
            timeout=120,
        )
        link = response.text.strip()
        if not link.startswith('https://'):
            raise ValueError(f'Invalid API response: {link[:100]}')
    except requests.Timeout:
        return jsonify(error='Litterbox upload timed out.'), 504
    except requests.RequestException as exc:
        return jsonify(error=f'Could not reach Litterbox: {exc}'), 502
    if not re.fullmatch(r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link):
        return jsonify(error=f'Litterbox rejected the upload (HTTP {response.status_code}).'), 502
    return jsonify(url=link), 200


@app.route('/health')
def health():
    return jsonify(status='ok'), 200
