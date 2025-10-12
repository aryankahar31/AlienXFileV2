from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import requests
import random
import string
import os
from io import BytesIO

app = Flask(__name__)
app.secret_key = "alienx_secret"

# Catbox max is 200MB
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB

# in-memory mapping: key -> {'link': '...', 'name': '...'}
uploaded_files = {}

def generate_key():
    return ''.join(random.choices(string.digits, k=4))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    mode = request.form.get('mode', 'file')
    uploads = []

    if mode == 'text':
        text = request.form.get('text', '').strip()
        if not text:
            return jsonify({"success": False, "error": "No text provided"}), 400

        filename = f"shared_text_{random.randint(1000, 9999)}.txt"
        file_stream = BytesIO(text.encode('utf-8'))
        file_stream.name = filename
        file_stream.seek(0)
        size = len(text.encode('utf-8'))

        if size > app.config['MAX_CONTENT_LENGTH']:
            return jsonify({"success": False, "error": "Text too large! Limit is 200 MB"}), 413

        try:
            upload_files = {'fileToUpload': (filename, file_stream, 'text/plain')}
            upload_data = {'reqtype': 'fileupload'}
            res = requests.post(
                "https://catbox.moe/user/api.php",
                data=upload_data,
                files=upload_files,
                timeout=300  # increased timeout for big files
            )
        except requests.exceptions.Timeout:
            return jsonify({"success": False, "error": "Upload timed out! File might be too large."}), 504
        except requests.exceptions.RequestException as e:
            return jsonify({"success": False, "error": "Request failed", "details": str(e)}), 500

        text_resp = res.text.strip()
        if res.status_code != 200 or not text_resp.startswith('https://files.catbox.moe/'):
            return jsonify({"success": False, "error": "catbox.moe returned failure", "details": text_resp or "Unknown error"}), 500

        key = generate_key()
        uploaded_files[key] = {'link': text_resp, 'name': filename}
        uploads.append({"key": key, "link": text_resp, "name": filename})

    else:  # file mode
        files = request.files.getlist('file')
        if not files or all(f.filename == '' for f in files):
            return jsonify({"success": False, "error": "No files provided"}), 400

        for file in files:
            if file.filename == '':
                continue

            file.seek(0, 2)
            size = file.tell()
            file.seek(0)
            if size > app.config['MAX_CONTENT_LENGTH']:
                return jsonify({"success": False, "error": f"File '{file.filename}' too large! Limit is 200 MB"}), 413

            try:
                upload_files = {'fileToUpload': (file.filename, file.stream, file.mimetype or 'application/octet-stream')}
                upload_data = {'reqtype': 'fileupload'}
                res = requests.post(
                    "https://catbox.moe/user/api.php",
                    data=upload_data,
                    files=upload_files,
                    timeout=300  # increased timeout
                )
            except requests.exceptions.Timeout:
                return jsonify({"success": False, "error": f"Upload of '{file.filename}' timed out! File might be too large."}), 504
            except requests.exceptions.RequestException as e:
                return jsonify({"success": False, "error": f"Request failed for '{file.filename}'", "details": str(e)}), 500

            text_resp = res.text.strip()
            if res.status_code != 200 or not text_resp.startswith('https://files.catbox.moe/'):
                return jsonify({"success": False, "error": f"catbox.moe failed for '{file.filename}'", "details": text_resp or "Unknown error"}), 500

            key = generate_key()
            uploaded_files[key] = {'link': text_resp, 'name': file.filename}
            uploads.append({"key": key, "link": text_resp, "name": file.filename})

    if not uploads:
        return jsonify({"success": False, "error": "No valid uploads"}), 400

    return jsonify({"success": True, "uploads": uploads})

@app.route('/download', methods=['GET', 'POST'])
def download_page():
    if request.method == 'POST':
        key = request.form.get('key', '').strip()
        file_info = uploaded_files.get(key)
        if not file_info:
            flash("Invalid or expired key!", "error")
            return redirect(url_for('download_page'))
        # redirect user to the catbox.moe link (or you could proxy)
        return redirect(file_info['link'])
    return render_template('download.html')

@app.route('/download/<key>')
def download_direct(key):
    file_info = uploaded_files.get(key)
    if not file_info:
        return "Invalid or expired key.", 404
    return redirect(file_info['link'])

@app.errorhandler(413)
def too_large(e):
    return "File too large! Limit is 200 MB", 413

if __name__ == '__main__':
    app.run(debug=True)