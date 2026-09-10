from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import random
import string
import logging
from io import BytesIO
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = Flask(__name__)

# ==================================================
# CONFIG
# ==================================================

app.secret_key = "alienx_secret"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 100MB limit
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Temporary RAM storage
uploaded_files = {}

# Expiry options
expire_delta = {
    '1h': timedelta(hours=1),
    '12h': timedelta(hours=12),
    '24h': timedelta(hours=24),
    '72h': timedelta(days=3)
}

# Dangerous extensions
banned_exts = {
    '.exe', '.scr', '.cpl',
    '.jar', '.bat', '.cmd',
    '.com', '.pif', '.vbs',
    '.wsf'
}

# ==================================================
# HELPERS
# ==================================================

def generate_key():
    while True:
        key = ''.join(random.choices(string.digits, k=4))
        if key not in uploaded_files:
            return key


def is_expired(file_info):
    if 'expires' not in file_info:
        return False
    return datetime.utcnow() > file_info['expires']


def create_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ==================================================
# ROUTES
# ==================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/download')
def download_page():
    return render_template('download.html')


# ==================================================
# UPLOAD
# ==================================================

@app.route('/upload', methods=['POST'])
def upload():

    mode = request.form.get('mode', 'file')
    expire_time = request.form.get('expire', '1h')

    uploads = []
    errors = []

    if expire_time not in expire_delta:
        expire_time = '1h'

    expires = datetime.utcnow() + expire_delta[expire_time]

    # ==========================================
    # TEXT MODE
    # ==========================================

    if mode == 'text':

        text = request.form.get('text', '').strip()

        if not text:
            return jsonify({
                "success": False,
                "error": "No text provided"
            }), 400

        key = generate_key()

        uploaded_files[key] = {
            'type': 'text',
            'content': text,
            'name': 'Shared Text',
            'expires': expires
        }

        direct_link = url_for(
            'download_direct',
            key=key,
            _external=True
        )

        logger.info(f"Text uploaded: Shared Text with key {key}")

        uploads.append({
            "key": key,
            "link": direct_link
        })

    # ==========================================
    # FILE MODE
    # ==========================================

    else:

        files = request.files.getlist('file')

        if not files:
            return jsonify({
                "success": False,
                "error": "No files selected"
            }), 400

        for f in files:

            if not f.filename:
                continue

            filename = secure_filename(f.filename)

            if not filename:
                continue

            # Check dangerous extensions
            if any(filename.lower().endswith(ext) for ext in banned_exts):
                logger.info(f"Banned extension attempted: {filename}")
                errors.append(f"{filename} is not allowed")
                continue

            try:

                session = create_session()

                response = session.post(
                    "https://litterbox.catbox.moe/resources/internals/api.php",
                    data={
                        'reqtype': 'fileupload',
                        'time': expire_time
                    },
                    files={
                        'fileToUpload': (
                            filename,
                            BytesIO(f.read())
                        )
                    },
                    timeout=120
                )

                link = response.text.strip()

                # Validate API response
                if not link.startswith("https://"):
                    raise ValueError(f"Invalid API response: {link[:100]}")

                key = generate_key()

                uploaded_files[key] = {
                    'type': 'file',
                    'link': link,
                    'name': filename,
                    'expires': expires
                }

                direct_link = url_for(
                    'download_direct',
                    key=key,
                    _external=True
                )

                logger.info(f"File uploaded: {filename} with key {key}")

                uploads.append({
                    "key": key,
                    "link": direct_link
                })

            except Exception as e:
                logger.error(f"Upload error ({filename}): {str(e)[:300]}")
                errors.append(f"{filename}: Upload failed")

    return jsonify({
        "success": True,
        "uploads": uploads,
        "errors": errors
    })


# ==================================================
# DOWNLOAD BY KEY
# ==================================================

@app.route('/download/<key>')
def download_direct(key):

    file_info = uploaded_files.get(key)

    if not file_info:
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Invalid Key</title></head>
        <body style="background:#0f0f0f;color:white;font-family:Arial;padding:40px;text-align:center;">
            <h2 style="color:red;">Invalid or expired key!</h2>
            <a href="/" style="color:#888;">Go Home</a>
        </body>
        </html>
        """, 404

    if is_expired(file_info):
        uploaded_files.pop(key, None)
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Expired</title></head>
        <body style="background:#0f0f0f;color:white;font-family:Arial;padding:40px;text-align:center;">
            <h2 style="color:orange;">File has expired!</h2>
            <a href="/" style="color:#888;">Go Home</a>
        </body>
        </html>
        """, 410

    # FILE — redirect to catbox link
    if file_info['type'] == 'file':
        file_link = file_info.get('link')
        if not file_link:
            return "Broken file link!", 500
        return redirect(file_link)

    # TEXT — display content
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{file_info['name']}</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                background: #0f0f0f;
                color: white;
                font-family: Arial;
                padding: 40px;
            }}
            .box {{
                background: #1b1b1b;
                padding: 20px;
                border-radius: 12px;
                white-space: pre-wrap;
                overflow-wrap: break-word;
            }}
            a {{
                color: #888;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <h2>{file_info['name']}</h2>
        <div class="box">{file_info['content']}</div>
        <br>
        <a href="/">Go Home</a>
    </body>
    </html>
    """


# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "success": False,
        "error": "Page not found"
    }), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify({
        "success": False,
        "error": "File too large (Max 100MB)"
    }), 413


@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500