from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import random
import string
import logging
from io import BytesIO
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "alienx_secret"  # In production, use os.environ.get('SECRET_KEY')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = app.logger

# Max upload size = 1GB
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024

# In-memory store {key: {type, content or link, name, expires}} - Consider Redis or DB for production
uploaded_files = {}

expire_delta = {
    '1h': timedelta(hours=1),
    '12h': timedelta(hours=12),
    '24h': timedelta(hours=24),
    '72h': timedelta(days=3)
}

def generate_key():
    """Generate a unique 4-digit key."""
    while True:
        key = ''.join(random.choices(string.digits, k=4))
        if key not in uploaded_files:
            return key

def is_expired(file_info):
    """Check if the upload has expired."""
    if 'expires' not in file_info:
        return False
    return datetime.utcnow() > file_info['expires']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    mode = request.form.get('mode', 'file')
    expire_time = request.form.get('expire', '1h')
    uploads = []
    errors = []

    # Validate expire_time
    valid_expires = {'1h', '12h', '24h', '72h'}
    if expire_time not in valid_expires:
        expire_time = '1h'
        logger.warning(f"Invalid expire_time '{expire_time}', defaulting to '1h'")

    delta = expire_delta[expire_time]
    expires = datetime.utcnow() + delta

    max_size = app.config['MAX_CONTENT_LENGTH']

    if mode == 'text':
        text = request.form.get('text', '').strip()
        if not text:
            return jsonify({"success": False, "error": "No text provided"}), 400

        size = len(text.encode('utf-8'))
        if size > max_size:
            return jsonify({"success": False, "error": f"Text too large! Limit is 1 GB ({size / (1024*1024*1024):.1f} GB)" }), 413

        name = 'Shared Text'
        key = generate_key()
        uploaded_files[key] = {
            'type': 'text',
            'content': text,
            'name': name,
            'expires': expires
        }
        link = url_for('download_direct', key=key, _external=True)
        uploads.append({"key": key, "link": link, "name": name})
        logger.info(f"Text uploaded: {name} with key {key}")

    else:  # file mode
        files_list = request.files.getlist('file')
        if not files_list or all(f.filename == '' for f in files_list):
            return jsonify({"success": False, "error": "No files provided"}), 400

        for f in files_list:
            if f.filename == '':
                continue

            # Secure filename
            filename = secure_filename(f.filename)

            # Check size
            f.seek(0, 2)
            size = f.tell()
            f.seek(0)
            if size > max_size:
                errors.append(f"File '{filename}' too large! Limit is 1 GB ({size / (1024*1024*1024):.1f} GB)")
                logger.warning(f"File too large: {filename}")
                continue

            data = {'reqtype': 'fileupload', 'time': expire_time}
            upload_files = {'fileToUpload': (filename, f.stream, f.mimetype or 'application/octet-stream')}
            try:
                res = requests.post("https://litterbox.catbox.moe/resources/internals/api.php",
                                    data=data, files=upload_files, timeout=300)
                text_resp = res.text.strip()
                if not text_resp.startswith('https://litter.catbox.moe/'):
                    raise ValueError(f"Invalid response: {text_resp}")
                key = generate_key()
                uploaded_files[key] = {
                    'type': 'file',
                    'link': text_resp,
                    'name': filename,
                    'expires': expires
                }
                uploads.append({"key": key, "link": text_resp, "name": filename})
                logger.info(f"File uploaded: {filename} with key {key}")
            except requests.exceptions.Timeout:
                errors.append(f"Upload of '{filename}' timed out! File might be too large.")
                logger.error(f"File upload timeout: {filename}")
            except requests.exceptions.RequestException as e:
                errors.append(f"Request failed for '{filename}': {str(e)}")
                logger.error(f"File upload request error: {filename} - {e}")
            except ValueError as e:
                errors.append(f"Catbox API failed for '{filename}': {str(e)}")
                logger.error(f"File upload API error: {filename} - {e}")
            except Exception as e:
                errors.append(f"Unexpected error for '{filename}': {str(e)}")
                logger.error(f"File upload unexpected error: {filename} - {e}")

    if not uploads and errors:
        return jsonify({"success": False, "errors": errors}), 400
    elif uploads and errors:
        return jsonify({"success": True, "uploads": uploads, "warnings": errors}), 200
    else:
        return jsonify({"success": True, "uploads": uploads})

@app.route('/download', methods=['GET', 'POST'])
def download_page():
    if request.method == 'POST':
        key = request.form.get('key', '').strip()
        if not key:
            return render_template('download.html', error="Please enter a key")
        file_info = uploaded_files.get(key)
        if not file_info or is_expired(file_info):
            if key in uploaded_files:
                del uploaded_files[key]
            return render_template('download.html', error="Invalid or expired key!")
        if file_info['type'] == 'file':
            return redirect(file_info['link'])
        else:
            return render_template('download.html', is_text=True, key=key, content=file_info['content'], name=file_info['name'])
    return render_template('download.html')

@app.route('/download/<key>')
def download_direct(key):
    file_info = uploaded_files.get(key)
    if not file_info or is_expired(file_info):
        if key in uploaded_files:
            del uploaded_files[key]
        return render_template('download.html', error="Invalid or expired key!")
    if file_info['type'] == 'file':
        return redirect(file_info['link'])
    else:
        return render_template('download.html', is_text=True, key=key, content=file_info['content'], name=file_info['name'])

@app.errorhandler(413)
def too_large(e):
    return "⚠️ File too large! Limit is 1 GB", 413

if __name__ == '__main__':
    app.run(debug=True)