"""AlienXFile V2 — Litterbox proxy for PythonAnywhere.

This small Flask app accepts file uploads from Render and forwards them to
Litterbox (litterbox.catbox.moe), bypassing Render's blocked IP range.

Shared-secret authentication prevents external abuse.

Deploy on PythonAnywhere:
  1. Upload this directory to ~/alienxfile_litterbox/
  2. Activate venv: source ~/alienxfile_litterbox/venv/bin/activate
  3. pip install Flask gunicorn requests requests-toolbelt (already done)
  4. Set LITTERBOX_PROXY_SECRET in the WSGI config (see below)
  5. Configure WSGI to import app from this module
"""

import os
import re

import requests
from flask import Flask, Response, jsonify, request
from requests_toolbelt.multipart.encoder import MultipartEncoder

app = Flask(__name__)

PROXY_SECRET = os.environ.get('LITTERBOX_PROXY_SECRET', '')
LITTERBOX_URL = 'https://litterbox.catbox.moe/resources/internals/api.php'


@app.route('/proxy/litterbox', methods=['POST'])
def proxy_upload():
    # --- Authentication ---
    auth = request.headers.get('X-Proxy-Secret', '')
    if not PROXY_SECRET or auth != PROXY_SECRET:
        return jsonify(error='Forbidden.'), 403

    # --- Validate forwarded fields ---
    expiry = request.form.get('time', '1h')
    if expiry not in {'1h', '12h', '24h', '72h'}:
        return jsonify(error='Invalid expiry.'), 400

    file = request.files.get('fileToUpload')
    if not file or not file.filename:
        return jsonify(error='No file provided.'), 400

    # --- Stream to Litterbox ---
    try:
        body = MultipartEncoder(fields={
            'reqtype': 'fileupload',
            'time': expiry,
            'fileToUpload': (file.filename, file.stream, file.content_type or 'application/octet-stream'),
        })
        resp = requests.post(
            LITTERBOX_URL,
            data=body,
            headers={'Content-Type': body.content_type},
            timeout=(10, 180),
            allow_redirects=False,
        )
    except requests.Timeout:
        return jsonify(error='Litterbox upload timed out.'), 504
    except requests.RequestException as exc:
        return jsonify(error=f'Could not reach Litterbox: {exc}'), 502

    link = resp.text.strip()
    if resp.status_code != 200 or not re.fullmatch(
        r'https://litter\.catbox\.moe/[A-Za-z0-9][A-Za-z0-9._-]*', link
    ):
        return jsonify(error=f'Litterbox rejected the upload (HTTP {resp.status_code}).'), 502

    return jsonify(url=link), 200


@app.route('/health')
def health():
    return jsonify(status='ok'), 200
