import os
import json
import re
import runpy
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
import base64
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from datetime import datetime
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

import qrcode
import requests
from flask import render_template, request
from requests_toolbelt.multipart.encoder import MultipartEncoder

from flask_app import app, get_db, save_share, _preview_category, download_folder_cipher


FILE_URL = 'https://litter.catbox.moe/abc123.txt'
BLOB_TOKEN = 'vercel_blob_rw_teststore_fakecredential'
BLOB_URL = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32 + '/report.pdf'


class Markup(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class DownloadTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='alienx-test-')
        self.addCleanup(directory.cleanup)
        self.database = str(Path(directory.name) / 'shares.sqlite3')
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(patch.dict(app.config, TESTING=True, DATABASE=self.database, DATABASE_URL=None, BLOB_READ_WRITE_TOKEN='',
                                     INDEXNOW_KEY='',
                                     UPLOAD_MAX_BYTES=1_000_000_000, LITTERBOX_MAX_BYTES=1_000_000_000,
                                     MAX_CONTENT_LENGTH=1_001_000_000,
                                     UPLOAD_RATE_LIMIT=1000, LOOKUP_RATE_LIMIT=1000,
                                     PREVIEW_RATE_LIMIT=1000, URL_META_RATE_LIMIT=1000,
                                     RATE_WINDOW_SECONDS=60, TRUST_PYTHONANYWHERE_PROXY=False, TRUST_RENDER_PROXY=False))
        self.now = 1_800_000_000
        self.clock = contexts.enter_context(patch('flask_app.time.time', return_value=self.now))
        contexts.enter_context(patch('flask_app.secrets.randbelow', side_effect=range(100_000)))
        # Fail closed: an accidentally unmocked external request must never upload data.
        contexts.enter_context(patch('requests.sessions.Session.request',
                                side_effect=AssertionError('Unexpected network request')))
        self.post = contexts.enter_context(patch('flask_app.requests.post',
                                           side_effect=AssertionError('Unexpected upload')))
        self.client = app.test_client()

    def mock_provider(self, link=FILE_URL, status=200):
        response = requests.Response()
        response.status_code = status
        response.url = 'https://litterbox.catbox.moe/resources/internals/api.php'
        response._content = link.encode('utf-8')
        response._content_consumed = True
        self.post.side_effect = None
        self.post.return_value = response
        return response

    def assert_download_form(self, response):
        tags = Markup(response.get_data(as_text=True)).tags
        forms = [attrs for tag, attrs in tags if tag == 'form']
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]['method'].lower(), 'post')
        self.assertEqual(forms[0]['action'], '/download')
        return next(attrs for tag, attrs in tags if tag == 'input' and attrs.get('name') == 'key')

    def test_text_xss_leading_zero_and_canonical_links(self):
        text = '<script>alert("xss")</script>\n<&\'\" \u00e9'
        with patch('flask_app.secrets.randbelow', return_value=7):
            response = self.client.post('/upload', data={
                'mode': 'text', 'text': '  ' + text + '  ', 'expire': '12h',
            })
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result['success'])
        self.assertEqual(result['errors'], [])
        share, = result['uploads']
        self.assertEqual(share['key'], '00007')
        self.assertEqual(share['type'], 'text')
        self.assertIsNone(share['storageProvider'])
        self.assertEqual(share['name'], 'Shared Text')
        self.assertEqual(share['size'], len(text.encode('utf-8')))
        self.assertNotIn('content', share)
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 43200)
        self.assertEqual(share['page_url'], 'http://localhost/share/00007')
        self.assertEqual(share['link'], 'http://localhost/download/00007')
        response = self.client.post('/download', data={'key': ' \t00007\n'})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, '/share/00007')
        for path in ('/share/00007', '/download/00007'):
            with self.subTest(path=path):
                page = self.client.get(path)
                self.assertEqual(page.status_code, 200)
                html = page.get_data(as_text=True)
                self.assertNotIn(text, html)
                self.assertIn('&lt;script&gt;alert(', html)
                self.assertIn('&lt;/script&gt;', html)
                self.assertIn('href="http://localhost/share/00007"', html)
                self.assertIn('<title>AlienXFile - Download by Code</title>', html)
                self.assertIn('noindex', page.headers['X-Robots-Tag'])
                self.assertIn('id="textContent"', html)
                self.assertEqual(page.headers['Cache-Control'], 'no-store')
                self.assertEqual(page.headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(page.headers['Referrer-Policy'], 'no-referrer')
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT content FROM shares').fetchone()[0], text)
        self.post.assert_not_called()

    def test_numeric_form_and_ascii_only_codes(self):
        response = self.client.get('/download')
        self.assertEqual(response.status_code, 200)
        field = self.assert_download_form(response)
        for name, value in {'type': 'text', 'inputmode': 'text', 'pattern': '[A-Za-z0-9]{3,20}',
                            'maxlength': '20', 'autocomplete': 'off'}.items():
            self.assertEqual(field[name], value)
        self.assertIn('required', field)
        for key in ('', 'ab', 'a' * 21, '+1234', '12.34', '12 34',
                    '\uff11\uff12\uff13\uff14\uff15', '\u0661\u0662\u0663\u0664\u0665',
                    "' OR 1=1", 'https://evil.example'):
            with self.subTest(key=key):
                response = self.client.post('/download', data={'key': key})
                self.assertEqual(response.status_code, 400)
        for key in ('00000', '99999', ' 00123 \n'):
            with self.subTest(valid=key):
                response = self.client.post('/download', data={'key': key})
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.location, '/share/' + key.strip())
        for prefix in ('/share/', '/download/'):
            for key in ('1234', '123456', '\uff11\uff12\uff13\uff14\uff15', '99999'):
                with self.subTest(path=prefix + key):
                    response = self.client.get(prefix + key)
                    self.assertEqual(response.status_code, 404)
                    self.assert_download_form(response)

    def test_template_escapes_name_title_input_and_error(self):
        payload = '\"><img src=x onerror=alert(1)><script>alert(2)</script>'
        response = self.client.post('/download', data={'key': payload})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.assert_download_form(response)['value'], payload)
        # Exercise attribute/error escaping even for values normally generated by the backend.
        with app.test_request_context('/download'):
            error_html = render_template('download.html', key=payload, error=payload)
            share_html = render_template('download.html', share={
                'name': payload, 'key': '00007', 'expires': payload, 'type': 'text',
                'content': payload, 'page_url': '/share/00007', 'link': '/download/00007',
            })
        for html in (response.get_data(as_text=True), error_html, share_html):
            self.assertNotIn(payload, html)
            self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
            tags = Markup(html).tags
            self.assertFalse(any('onerror' in attrs for tag, attrs in tags))
            self.assertTrue(all(attrs.get('src') == '/qr/00007' for tag, attrs in tags if tag == 'img' and attrs.get('src')))
        time_tag = next(attrs for tag, attrs in Markup(share_html).tags if tag == 'time')
        self.assertEqual(time_tag['title'], payload + ' (UTC)')
        self.assertEqual(time_tag['datetime'], payload)
        self.assertIn('<h1>&#34;&gt;&lt;img', share_html)
        self.assertIn('role="alert"', error_html)

    def test_file_upload_streams_multipart_and_exposes_details(self):
        payload = b'\x00streamed\r\nfile\xff' * 1000
        provider = self.mock_provider(' \n' + FILE_URL + '\n')

        def consume(url, **kwargs):
            self.assertEqual(url, provider.url)
            self.assertNotIn('files', kwargs)
            body = kwargs['data']
            self.assertIsInstance(body, MultipartEncoder)
            self.assertNotIsInstance(body, (bytes, bytearray, str))
            self.assertIs(body.fields['fileToUpload'][1], request.files['file'].stream)
            self.assertEqual(kwargs['headers']['Content-Type'], body.content_type)
            self.assertEqual(kwargs['timeout'], (10, 180))
            self.assertFalse(kwargs['allow_redirects'])
            chunks = list(iter(lambda: body.read(113), b''))
            self.assertGreater(len(chunks), 1)
            self.assertTrue(all(len(chunk) <= 113 for chunk in chunks))
            wire = b''.join(chunks)
            self.assertEqual(len(wire), body.len)
            message = BytesParser(policy=policy.default).parsebytes(
                ('Content-Type: ' + body.content_type + '\r\n\r\n').encode() + wire)
            parts = {part.get_param('name', header='content-disposition'): part
                     for part in message.iter_parts()}
            self.assertEqual(set(parts), {'reqtype', 'time', 'fileToUpload'})
            self.assertEqual(parts['reqtype'].get_payload(decode=True), b'fileupload')
            self.assertEqual(parts['time'].get_payload(decode=True), b'24h')
            self.assertEqual(parts['fileToUpload'].get_filename(), 'my_report.txt')
            self.assertEqual(parts['fileToUpload'].get_content_type(), 'application/octet-stream')
            self.assertEqual(parts['fileToUpload'].get_payload(decode=True), payload)
            return provider

        self.post.side_effect = consume
        with patch('flask_app.secrets.randbelow', return_value=42), \
                patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put', side_effect=AssertionError('Unexpected Blob upload')) as put:
            response = self.client.post('/upload', data={
                'storageProvider': 'litterbox', 'expire': '24h',
                'file': (BytesIO(payload), '../../my report?.txt'),
            })
            put.assert_not_called()
        self.assertEqual(response.status_code, 200)
        share, = response.get_json()['uploads']
        self.assertEqual(share['key'], '00042')
        self.assertEqual(share['type'], 'file')
        self.assertEqual(share['storageProvider'], 'litterbox')
        self.assertEqual(share['name'], 'my_report.txt')
        self.assertEqual(share['size'], len(payload))
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 86400)
        self.assertEqual(share['page_url'], 'http://localhost/share/00042')
        self.assertEqual(share['link'], 'http://localhost/download/00042')
        details = self.client.get('/share/00042')
        self.assertEqual(details.status_code, 200)
        self.assertIn(b'my_report.txt', details.data)
        self.assertIn(f'({len(payload)} bytes)'.encode(), details.data)
        self.assertIn(b'href="http://localhost/download/00042"', details.data)
        self.assertIn(b'href="http://localhost/share/00042"', details.data)
        self.assertNotIn(FILE_URL.encode(), details.data)
        direct = self.client.get('/download/00042')
        self.assertEqual(direct.status_code, 302)
        self.assertEqual(direct.location, FILE_URL)
        self.assertIn('noindex', direct.headers['X-Robots-Tag'])
        self.post.assert_called_once()

    def test_invalid_provider_links_do_not_create_shares(self):
        for link in ('', 'javascript:alert(1)', 'http://litter.catbox.moe/a.txt',
                     'https://evil.example/a.txt', 'https://litter.catbox.moe.evil.example/a.txt',
                     'https://user@litter.catbox.moe/a.txt', 'https://litter.catbox.moe:443/a.txt',
                     'https://litter.catbox.moe/', 'https://litter.catbox.moe/../a.txt',
                     'https://litter.catbox.moe/a/b.txt', FILE_URL + '?x=1', FILE_URL + '#x',
                     'https://litter.catbox.moe/a\nb.txt', 'https://litter.catbox.moe/a\tb.txt'):
            with self.subTest(link=link):
                self.mock_provider(link)
                response = self.client.post('/upload', data={
                    'storageProvider': 'litterbox', 'file': (BytesIO(b'x'), 'test.txt'),
                })
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()['success'])
                self.assertEqual(response.get_json()['uploads'], [])
                self.assertEqual(len(response.get_json()['errors']), 1)
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)

    def test_provider_http_errors_do_not_create_shares(self):
        for status in (301, 302, 307, 400, 403, 429, 500, 503):
            with self.subTest(status=status), patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                    patch('flask_app.requests.put', side_effect=AssertionError('Unexpected Blob fallback')) as put:
                self.mock_provider('<html><body>private upstream detail</body></html>', status=status)
                response = self.client.post('/upload', data={
                    'storageProvider': 'litterbox', 'file': (BytesIO(b'x'), 'test.txt'),
                })
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()['success'])
                self.assertEqual(response.get_json()['uploads'], [])
                self.assertEqual(len(response.get_json()['errors']), 1)
                self.assertNotIn(b'<html', response.data)
                self.assertNotIn(b'private upstream detail', response.data)
                if status == 403:
                    self.assertIn('HTTP 403', response.get_json()['errors'][0])
                put.assert_not_called()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)

    def test_provider_transport_errors_are_safe(self):
        for error in (requests.Timeout('private provider detail'),
                      requests.ConnectionError('private provider detail')):
            with self.subTest(error=type(error).__name__), patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                    patch('flask_app.requests.put', side_effect=AssertionError('Unexpected Blob fallback')) as put:
                self.post.side_effect = error
                response = self.client.post('/upload', data={
                    'storageProvider': 'litterbox', 'file': (BytesIO(b'x'), 'test.txt'),
                })
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()['success'])
                self.assertEqual(response.get_json()['uploads'], [])
                self.assertEqual(len(response.get_json()['errors']), 1)
                self.assertNotIn(b'private provider detail', response.data)
                if isinstance(error, requests.Timeout):
                    self.assertRegex(response.get_json()['errors'][0].lower(), r'timed out|timeout')
                put.assert_not_called()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)

    def test_all_failed_and_partial_file_batches(self):
        response = self.client.post('/upload', data={'storageProvider': 'litterbox', 'file': [
            (BytesIO(b'x'), 'BAD.EXE'), (BytesIO(b'x'), '../../'),
        ]})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()['success'])
        self.assertEqual(response.get_json()['uploads'], [])
        self.assertEqual(len(response.get_json()['errors']), 2)
        self.post.assert_not_called()
        provider = self.mock_provider()
        self.post.side_effect = [provider, requests.Timeout('private')]
        response = self.client.post('/upload', data={'storageProvider': 'litterbox', 'file': [
            (BytesIO(b'good'), 'good.txt'), (BytesIO(b'x'), 'bad.CmD'),
            (BytesIO(b'failed'), 'failed.txt'),
        ]})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result['success'])
        self.assertEqual([share['name'] for share in result['uploads']], ['good.txt'])
        self.assertEqual(len(result['errors']), 2)
        self.assertEqual(self.post.call_count, 2)
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 1)

    def test_upload_validation_and_text_limit(self):
        with patch.dict(app.config, MAX_TEXT_LENGTH=4):
            for data in ({}, {'mode': 'invalid'}, {'mode': 'text', 'expire': 'forever', 'text': 'ok'},
                         {'mode': 'text', 'text': ''}, {'mode': 'text', 'text': '   '},
                          {'mode': 'text', 'text': '12345'},
                          {'mode': 'text', 'text': '\x00'},
                         {'storageProvider': 'litterbox', 'file': [(BytesIO(b'x'), f'{i}.txt') for i in range(11)]},
                         {'storageProvider': 'litterbox', 'file': (BytesIO(b'x'), 'a' * 256 + '.txt')}):
                with self.subTest(data=data):
                    response = self.client.post('/upload', data=data)
                    self.assertEqual(response.status_code, 400)
                    self.assertFalse(response.get_json()['success'])
                    self.assertEqual(response.get_json()['uploads'], [])
            response = self.client.post('/upload', data={'mode': 'text', 'text': ' \u00e9abc '})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['uploads'][0]['size'], 5)
            response = self.client.post('/upload', data={'mode': 'text', 'text': 'a\r\nbc'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['uploads'][0]['size'], 4)
        self.post.assert_not_called()

    def test_request_limits_return_correct_error_formats(self):
        with patch.dict(app.config, MAX_CONTENT_LENGTH=512, UPLOAD_MAX_BYTES=512):
            response = self.client.post('/upload', data={
                'storageProvider': 'litterbox', 'file': (BytesIO(b'x' * 513), 'big.txt'),
            })
            self.assertEqual(response.status_code, 413)
            self.assertFalse(response.get_json()['success'])
            self.assertEqual(response.get_json()['uploads'], [])
            self.assertTrue(response.get_json()['error'])
        response = self.client.post('/download', data={'key': '1' * 4097})
        self.assertEqual(response.status_code, 413)
        self.assert_download_form(response)
        self.post.assert_not_called()

    def test_per_file_limit_includes_boundary_not_multipart_overhead(self):
        self.mock_provider()
        with patch.dict(app.config, UPLOAD_MAX_BYTES=8, LITTERBOX_MAX_BYTES=32,
                        MAX_CONTENT_LENGTH=4096, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            for provider, size, status in (
                ('vercel', 0, 200), ('vercel', 8, 200), ('vercel', 9, 200),
                ('litterbox', 0, 200), ('litterbox', 9, 200),
                ('litterbox', 32, 200), ('litterbox', 33, 400),
            ):
                with self.subTest(provider=provider, size=size):
                    calls = put.call_count, self.post.call_count
                    response = self.client.post('/upload', data={
                        'storageProvider': provider,
                        'file': (BytesIO(b'x' * size), 'sized.txt'),
                    })
                    self.assertEqual(response.status_code, status)
                    self.assertEqual(response.get_json()['success'], status == 200)
                    if status == 400:
                        self.assertEqual(response.get_json()['uploads'], [])
                        self.assertEqual((put.call_count, self.post.call_count), calls)
            self.assertEqual(put.call_count, 2)
            self.assertEqual(self.post.call_count, 4)
            for provider, size in (('vercel', 8), ('litterbox', 32)):
                response = self.client.post('/upload', data={'storageProvider': provider, 'file': [
                    (BytesIO(b'x' * size), 'one.txt'), (BytesIO(b'y' * size), 'two.txt'),
                ]})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.get_json()['uploads']), 2)
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 10)

    def test_provider_selection_and_all_expiration_mappings(self):
        self.mock_provider()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            for expiry, seconds in (('1h', 3600), ('12h', 43200), ('24h', 86400), ('72h', 259200)):
                for provider in ('vercel', 'litterbox'):
                    with self.subTest(provider=provider, expiry=expiry):
                        put.reset_mock()
                        self.post.reset_mock()
                        response = self.client.post('/upload', data={
                            'storageProvider': provider, 'expire': expiry,
                            'file': (BytesIO(b'x'), 'test.txt'),
                        })
                        self.assertEqual(response.status_code, 200)
                        share, = response.get_json()['uploads']
                        self.assertEqual(share['storageProvider'], provider)
                        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + seconds)
                        with app.app_context():
                            row = get_db().execute('SELECT * FROM shares WHERE key = ?', (share['key'],)).fetchone()
                            self.assertEqual(row['provider'], provider)
                            self.assertEqual(row['url'], BLOB_URL if provider == 'vercel' else FILE_URL)
                        if provider == 'vercel':
                            put.assert_called_once()
                            self.post.assert_not_called()
                        else:
                            put.assert_not_called()
                            self.post.assert_called_once()
                            self.assertEqual(self.post.call_args.kwargs['data'].fields['time'], expiry)

    def test_invalid_provider_and_missing_blob_token_never_fall_back(self):
        with patch('flask_app.requests.put') as put:
            for provider in ('', 'Vercel', 'unknown'):
                response = self.client.post('/upload', data={
                    'storageProvider': provider, 'file': (BytesIO(b'x'), 'test.txt'),
                })
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()['success'])
                self.assertEqual(response.get_json()['uploads'], [])
            for selection in ({}, {'storageProvider': 'vercel'}):
                for count, status in ((0, 400), (11, 400), (1, 503)):
                    with self.subTest(selection=selection, count=count):
                        response = self.client.post('/upload', data={
                            **selection, 'file': [(BytesIO(b'x'), f'{i}.txt') for i in range(count)],
                        })
                        self.assertEqual(response.status_code, status)
                        self.assertFalse(response.get_json()['success'])
                        self.assertEqual(response.get_json()['uploads'], [])
                        self.assertTrue(response.get_json()['error'])
            put.assert_not_called()
        self.post.assert_not_called()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)

    def test_vercel_failure_falls_back_to_litterbox(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put', side_effect=requests.Timeout('private detail')) as put:
            self.mock_provider()
            response = self.client.post('/upload', data={
                'storageProvider': 'vercel', 'file': (BytesIO(b'x'), 'test.txt'),
            })
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.get_json()['success'])
            self.assertEqual(len(response.get_json()['uploads']), 1)
            self.assertNotIn(b'private detail', response.data)
            put.assert_called_once()
        self.post.assert_called_once()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 1)

    def test_text_ignores_storage_provider_and_keeps_null_metadata(self):
        with patch('flask_app.requests.put') as put:
            for token in ('', BLOB_TOKEN):
                for provider in ('vercel', 'litterbox', 'invalid'):
                    with self.subTest(token_configured=bool(token), provider=provider), \
                            patch.dict(app.config, BLOB_READ_WRITE_TOKEN=token):
                        response = self.client.post('/upload', data={
                            'mode': 'text', 'text': 'database only', 'storageProvider': provider,
                        })
                        self.assertEqual(response.status_code, 200)
                        share, = response.get_json()['uploads']
                        self.assertIsNone(share['storageProvider'])
                        with app.app_context():
                            row = get_db().execute('SELECT content, provider FROM shares WHERE key = ?',
                                                   (share['key'],)).fetchone()
                            self.assertEqual(tuple(row), ('database only', None))
            put.assert_not_called()
        self.post.assert_not_called()

    def test_vercel_limit_message_uses_decimal_1_gb(self):
        stream = BytesIO()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask.wrappers.Request._get_file_stream', return_value=stream), \
                patch.object(stream, 'tell', return_value=1_000_000_001), \
                patch('flask_app.requests.put') as put:
            response = self.client.post('/upload', data={
                'storageProvider': 'vercel', 'file': (BytesIO(b'x'), 'large.txt'),
            })
            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.get_json()['success'])
            self.assertEqual(response.get_json()['uploads'], [])
            error, = response.get_json()['errors']
            self.assertIn('1 GB', error)

    def test_default_provider_limits_leave_room_for_litterbox_requests(self):
        result = subprocess.run([sys.executable, '-B', '-c', '''
from flask_app import app
assert app.config['UPLOAD_MAX_BYTES'] == 1_000_000_000
assert app.config['LITTERBOX_MAX_BYTES'] == 1_000_000_000
assert app.config['MAX_CONTENT_LENGTH'] == 1_001_000_000
'''], cwd=Path(__file__).resolve().parent,
            env={**{key: value for key, value in os.environ.items()
                    if key not in {'ALIENX_UPLOAD_MAX_BYTES', 'ALIENX_LITTERBOX_MAX_BYTES'}},
                 'DATABASE_URL': '', 'RENDER': '', 'ALIENX_DATABASE': self.database,
                 'BLOB_READ_WRITE_TOKEN': ''},
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, 'Default storage limits did not match the provider contract')

    def test_sqlite_legacy_migration_preserves_data_and_codes(self):
        columns = ('key', 'type', 'name', 'content', 'url', 'size', 'expires')
        legacy = [
            ('00007', 'text', 'Shared Text', 'legacy note', None, 11, self.now + 3600),
            ('00008', 'file', 'report.pdf', None, BLOB_URL, 9, self.now + 3600),
            ('00009', 'file', 'test.txt', None, FILE_URL, 1, self.now + 3600),
            ('00010', 'file', 'expired.txt', None, FILE_URL, 1, self.now - 1),
        ]
        with closing(sqlite3.connect(self.database)) as db, db:
            db.executescript('''
                CREATE TABLE shares (
                    key TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
                    content TEXT, url TEXT, size INTEGER NOT NULL, expires DOUBLE PRECISION NOT NULL
                );
                CREATE INDEX shares_expiry ON shares(expires);
                CREATE TABLE rate_limits (
                    ip TEXT NOT NULL, action TEXT NOT NULL, started DOUBLE PRECISION NOT NULL,
                    hits INTEGER NOT NULL, PRIMARY KEY (ip, action)
                );
            ''')
            db.executemany('''INSERT INTO shares (key, type, name, content, url, size, expires)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''', legacy)
            db.execute('INSERT INTO rate_limits VALUES (?, ?, ?, ?)',
                       ('198.51.100.7', 'upload', self.now - 10, 3))
        for _ in range(2):
            with app.app_context():
                db = get_db()
                schema = db.execute('PRAGMA table_info(shares)').fetchall()
                self.assertEqual([row['name'] for row in schema],
                                 [*columns, 'provider', 'salt', 'iv', 'is_encrypted'])
                self.assertEqual(schema[-1]['type'].upper(), 'INTEGER')
                rows = db.execute('SELECT * FROM shares ORDER BY key').fetchall()
                self.assertEqual([tuple(row[name] for name in columns) for row in rows], legacy)
                self.assertEqual([row['provider'] for row in rows], [None, 'vercel', 'litterbox', 'litterbox'])
                rate, = db.execute('SELECT * FROM rate_limits').fetchall()
                self.assertEqual(tuple(rate), ('198.51.100.7', 'upload', self.now - 10, 3))
                self.assertIn('shares_expiry', [row['name'] for row in db.execute('PRAGMA index_list(shares)')])
        self.assertIn(b'legacy note', self.client.get('/share/00007').data)
        self.assertEqual(self.client.get('/share/00008').status_code, 200)
        self.assertEqual(self.client.get('/download/00009').location, FILE_URL)
        self.assertEqual(self.client.get('/download/00010').status_code, 410)
        self.assertEqual(self.client.get('/download/00010').status_code, 404)
        self.post.assert_not_called()

    def test_shares_persist_across_contexts_and_fresh_process(self):
        with app.app_context():
            response = app.test_client().post('/upload', data={'mode': 'text', 'text': 'persistent note'})
            self.assertEqual(response.status_code, 200)
            key = response.get_json()['uploads'][0]['key']
        with app.app_context():
            response = app.test_client().get('/share/' + key)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'persistent note', response.data)
        result = subprocess.run(
            [sys.executable, '-B', '-c', '''
import sys
from unittest.mock import patch
from flask_app import app
with patch('flask_app.time.time', return_value=float(sys.argv[2])), patch(
        'requests.sessions.Session.request', side_effect=AssertionError('Unexpected network')):
    response = app.test_client().get('/share/' + sys.argv[1])
    assert response.status_code == 200, response.status_code
    assert b'persistent note' in response.data
''', key, str(self.now)],
            cwd=Path(__file__).resolve().parent,
            env={**os.environ, 'ALIENX_DATABASE': self.database, 'ALIENX_PYTHONANYWHERE': '0',
                 'DATABASE_URL': '', 'RENDER': '', 'PYTHONDONTWRITEBYTECODE': '1'},
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_collision_retry_and_exhaustion_never_overwrite(self):
        with patch('flask_app.secrets.randbelow', return_value=7):
            first = self.client.post('/upload', data={'mode': 'text', 'text': 'original'})
        self.assertEqual(first.status_code, 200)
        with patch('flask_app.secrets.randbelow', side_effect=[7, 8]) as random:
            second = self.client.post('/upload', data={'mode': 'text', 'text': 'second'})
            self.assertEqual(second.status_code, 200)
            self.assertEqual(second.get_json()['uploads'][0]['key'], '00008')
            self.assertEqual(random.call_count, 2)
        with patch('flask_app.secrets.randbelow', return_value=7) as random:
            failed = self.client.post('/upload', data={'mode': 'text', 'text': 'overwrite'})
            self.assertEqual(failed.status_code, 503)
            self.assertFalse(failed.get_json()['success'])
            self.assertEqual(failed.get_json()['uploads'], [])
            self.assertEqual(random.call_count, 100)
        with app.app_context():
            rows = get_db().execute('SELECT key, content FROM shares ORDER BY key').fetchall()
            self.assertEqual([tuple(row) for row in rows], [('00007', 'original'), ('00008', 'second')])

    def test_concurrent_connections_do_not_lose_shares_or_rate_counts(self):
        def upload(index):
            return app.test_client().post('/upload', data={'mode': 'text', 'text': str(index)})

        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(upload, range(12)))
        self.assertTrue(all(response.status_code == 200 for response in responses))
        keys = {response.get_json()['uploads'][0]['key'] for response in responses}
        self.assertEqual(len(keys), 12)
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 12)
            self.assertEqual(get_db().execute('SELECT hits FROM rate_limits WHERE action = "upload"').fetchone()[0], 12)

    def test_qr_is_local_svg_and_obeys_expiry_and_rate_limits(self):
        response = self.client.post('/upload', data={'mode': 'text', 'text': 'scan me'})
        share = response.get_json()['uploads'][0]
        path = '/qr/' + share['key']
        with patch('flask_app.qrcode.make', wraps=qrcode.make) as make:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, 'image/svg+xml')
            self.assertIn('noindex', response.headers['X-Robots-Tag'])
            self.assertEqual(make.call_args.args[0], share['page_url'])
        root = ElementTree.fromstring(response.data)
        self.assertEqual(root.tag, '{http://www.w3.org/2000/svg}svg')
        self.assertIsNotNone(root.find('{http://www.w3.org/2000/svg}path'))
        self.assertNotIn(b'<script', response.data)
        with patch.dict(app.config, LOOKUP_RATE_LIMIT=1):
            self.assertEqual(self.client.get(path).status_code, 429)
        self.clock.return_value = self.now + 3600
        self.assertEqual(self.client.get(path).status_code, 410)
        self.assertEqual(self.client.get(path).status_code, 404)
        self.post.assert_not_called()

    def test_expiry_on_both_routes_removes_text_and_file_shares(self):
        self.mock_provider()
        for kind in ('text', 'file'):
            for route in ('/share/', '/download/'):
                with self.subTest(kind=kind, route=route):
                    self.clock.return_value = self.now
                    data = {'mode': 'text', 'text': 'expires'} if kind == 'text' else {
                        'storageProvider': 'litterbox', 'file': (BytesIO(b'x'), 'expires.txt'),
                    }
                    response = self.client.post('/upload', data=data)
                    self.assertEqual(response.status_code, 200)
                    key = response.get_json()['uploads'][0]['key']
                    self.clock.return_value = self.now + 3599
                    self.assertEqual(self.client.get(route + key).status_code,
                                     302 if kind == 'file' and route == '/download/' else 200)
                    self.clock.return_value = self.now + 3600
                    expired = self.client.get(route + key)
                    self.assertEqual(expired.status_code, 410)
                    self.assert_download_form(expired)
                    self.assertEqual(self.client.get(route + key).status_code, 404)
                    with app.app_context():
                        self.assertIsNone(get_db().execute('SELECT key FROM shares WHERE key = ?',
                                                         (key,)).fetchone())

    def test_lookup_rate_shared_by_routes_contexts_but_not_ips_or_uploads(self):
        with patch.dict(app.config, LOOKUP_RATE_LIMIT=2):
            with app.app_context():
                self.assertEqual(app.test_client().get('/share/99999').status_code, 404)
            with app.app_context():
                self.assertEqual(app.test_client().post('/download', data={'key': '99999'}).status_code, 303)
            self.clock.return_value = self.now + 10
            for method, path in (('GET', '/download/99999'), ('GET', '/share/99999'), ('POST', '/download')):
                with self.subTest(method=method, path=path):
                    response = app.test_client().open(path, method=method, data={'key': '99999'})
                    self.assertEqual(response.status_code, 429)
                    self.assertIn(int(response.headers['Retry-After']), (50, 51))
                    self.assert_download_form(response)
            self.assertEqual(self.client.get('/share/99999',
                             environ_overrides={'REMOTE_ADDR': '198.51.100.2'}).status_code, 404)
            self.assertEqual(self.client.post('/upload', data={'mode': 'text', 'text': 'separate'}).status_code, 200)
            self.assertEqual(self.client.get('/download').status_code, 200)
            self.clock.return_value = self.now + 60
            self.assertEqual(self.client.get('/download/99999').status_code, 404)
            self.assertEqual(self.client.post('/download', data={'key': '99999'}).status_code, 303)

    def test_upload_rate_persists_and_local_spoofed_headers_are_ignored(self):
        with patch.dict(app.config, UPLOAD_RATE_LIMIT=1):
            for index, status in ((1, 400), (2, 429)):
                with app.app_context():
                    response = app.test_client().post('/upload', headers={
                        'X-Real-IP': f'198.51.100.{index}',
                        'X-Forwarded-For': f'203.0.113.{index}',
                        'CF-Connecting-IP': f'203.0.113.{index}',
                    })
                self.assertEqual(response.status_code, status)
            self.assertFalse(response.get_json()['success'])
            self.assertEqual(response.get_json()['uploads'], [])
            self.assertIn(int(response.headers['Retry-After']), (60, 61))
            self.assertEqual(self.client.post('/upload',
                             environ_overrides={'REMOTE_ADDR': '198.51.100.2'}).status_code, 400)
            self.assertEqual(self.client.get('/share/99999').status_code, 404)
            self.clock.return_value = self.now + 60
            self.assertEqual(self.client.post('/upload').status_code, 400)
        self.post.assert_not_called()

    def test_trusted_pythonanywhere_uses_real_ip_not_forwarded_for(self):
        with patch.dict(app.config, UPLOAD_RATE_LIMIT=1, TRUST_PYTHONANYWHERE_PROXY=True):
            for real_ip, forwarded, status in (
                ('198.51.100.1', '203.0.113.1', 400),
                ('198.51.100.1', '203.0.113.2', 429),
                ('198.51.100.2', '203.0.113.1', 400),
                ('invalid-one', '203.0.113.3', 400),
                ('invalid-two', '203.0.113.4', 429),
                ('2001:db8::1', '203.0.113.5', 400),
                ('2001:0db8:0:0:0:0:0:1', '203.0.113.6', 429),
            ):
                with self.subTest(real_ip=real_ip, forwarded=forwarded):
                    response = app.test_client().post('/upload', headers={
                        'X-Real-IP': real_ip, 'X-Forwarded-For': forwarded,
                    })
                    self.assertEqual(response.status_code, status)
            self.assertEqual(self.client.post('/upload').status_code, 400)
            response = self.client.post('/upload', headers={'X-Forwarded-For': '203.0.113.99'})
            self.assertEqual(response.status_code, 429)
            self.assertIn('Retry-After', response.headers)
        self.post.assert_not_called()

    def test_render_uses_edge_ip_and_ignores_other_client_headers(self):
        with patch.dict(app.config, TRUST_RENDER_PROXY=True, UPLOAD_RATE_LIMIT=1):
            for real_ip, forwarded, status in (
                ('198.51.100.1', '203.0.113.1', 400),
                ('198.51.100.1', '203.0.113.2', 429),
                ('198.51.100.2', '203.0.113.1', 400),
                ('', '203.0.113.3', 400),
                ('not-an-ip', '203.0.113.4', 429),
            ):
                response = self.client.post('/upload', headers={
                    'CF-Connecting-IP': real_ip, 'X-Forwarded-For': forwarded, 'X-Real-IP': forwarded,
                })
                self.assertEqual(response.status_code, status)

    def test_render_requires_persistent_database_and_restricts_proxy_scheme(self):
        result = subprocess.run([sys.executable, '-B', '-c', 'import flask_app'],
                                cwd=Path(__file__).resolve().parent,
                                env={**os.environ, 'RENDER': 'true', 'DATABASE_URL': ''},
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Set DATABASE_URL', result.stderr)
        for render, expected in (('true', '*'), ('', '')):
            with patch.dict(os.environ, RENDER=render, RENDER_SERVICE_TYPE='web', PORT='9090'):
                config = runpy.run_path(str(Path(__file__).with_name('gunicorn.conf.py')))
            self.assertEqual(config['bind'], '0.0.0.0:9090')
            self.assertEqual(config['forwarded_allow_ips'], expected)
            self.assertEqual(config['forwarder_headers'], '')
            self.assertEqual(config['secure_scheme_headers'], {'X-FORWARDED-PROTO': 'https'} if render else {})

    def test_private_blob_streaming_download_and_expired_cleanup(self):
        token = 'vercel_blob_rw_teststore_fakecredential'
        url = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32 + '/report.pdf'
        self.mock_provider()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=token), \
                patch('flask_app.requests.put') as put, patch('flask_app.requests.get') as get:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': url}
            response = self.client.post('/upload', data={'file': (BytesIO(b'PDF bytes'), 'report.pdf')})
            self.assertEqual(response.status_code, 200)
            share = response.get_json()['uploads'][0]
            self.assertEqual(share['storageProvider'], 'vercel')
            with app.app_context():
                db = get_db()
                columns = {col['name'] for col in db.execute('PRAGMA table_info(shares)').fetchall()}
                self.assertIn('provider', columns)
                self.assertIn('salt', columns)
                self.assertIn('iv', columns)
                self.assertIn('is_encrypted', columns)
                row = db.execute('SELECT provider FROM shares WHERE key = ?', (share['key'],)).fetchone()
                self.assertEqual(row['provider'], 'vercel')
            self.assertEqual(put.call_args.kwargs['headers']['x-vercel-blob-access'], 'private')
            self.assertEqual(put.call_args.kwargs['headers']['Authorization'], 'Bearer ' + token)
            self.assertEqual(put.call_args.kwargs['headers']['Content-Length'], '9')
            self.assertNotIsInstance(put.call_args.kwargs['data'], bytes)
            self.assertFalse(put.call_args.kwargs['allow_redirects'])
            self.assertNotIn(token.encode(), response.data)
            upstream = get.return_value
            upstream.status_code = 200
            upstream.iter_content.return_value = iter([b'PDF ', b'bytes'])
            downloaded = self.client.get('/download/' + share['key'])
            self.assertEqual(downloaded.status_code, 200)
            self.assertEqual(downloaded.data, b'PDF bytes')
            self.assertEqual(downloaded.headers['Content-Length'], '9')
            self.assertIn('attachment;', downloaded.headers['Content-Disposition'])
            self.assertEqual(downloaded.headers['Cache-Control'], 'no-store')
            self.assertIn('noindex', downloaded.headers['X-Robots-Tag'])
            self.assertEqual(get.call_args.args[0], url)
            self.assertEqual(get.call_args.kwargs['headers']['Authorization'], 'Bearer ' + token)
            self.assertFalse(get.call_args.kwargs['allow_redirects'])
            downloaded.close()
            upstream.close.assert_called_once()
            self.clock.return_value = self.now + 3600
            self.assertEqual(self.client.get('/download/' + share['key']).status_code, 410)
            self.assertEqual(self.post.call_args.args[0], 'https://vercel.com/api/blob/delete')
            self.assertEqual(self.post.call_args.kwargs['json'], {'urls': [url]})
            self.assertEqual(self.client.get('/download/' + share['key']).status_code, 404)

    def test_private_blob_cleanup_failure_keeps_metadata_for_retry(self):
        token = 'vercel_blob_rw_teststore_fakecredential'
        url = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32 + '/report.pdf'
        with app.app_context():
            db = get_db()
            with db:
                db.execute('''INSERT INTO shares (key, type, name, content, url, size, expires, provider)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                           ('00007', 'file', 'report.pdf', None, url, 9, self.now - 1, 'vercel'))
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=token):
            self.mock_provider(status=503)
            self.assertEqual(self.client.get('/download/00007').status_code, 410)
            with app.app_context():
                self.assertIsNotNone(get_db().execute('SELECT key FROM shares WHERE key = ?', ('00007',)).fetchone())
            self.mock_provider(status=200)
            self.assertEqual(self.client.get('/download/00007').status_code, 410)
            self.assertEqual(self.client.get('/download/00007').status_code, 404)

    def test_private_blob_never_sends_token_to_untrusted_url(self):
        token = 'vercel_blob_rw_teststore_fakecredential'
        prefix = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=token), patch('flask_app.requests.get') as get:
            for url in ('https://evil.example/file', prefix + '/a.pdf?redirect=1',
                        prefix + '/a\nb.pdf', prefix.replace('teststore.', 'otherstore.') + '/a.pdf'):
                with app.app_context():
                    db = get_db()
                    with db:
                        db.execute('''INSERT OR REPLACE INTO shares
                                      (key, type, name, content, url, size, expires, provider)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                   ('00007', 'file', 'report.pdf', None, url, 9, self.now + 3600, 'vercel'))
                self.assertEqual(self.client.get('/download/00007').status_code, 502)
            get.assert_not_called()

    def test_download_uses_persisted_provider_and_validates_redirects(self):
        cases = [
            ('litterbox', FILE_URL, 302), ('vercel', FILE_URL, 502),
            ('litterbox', BLOB_URL, 502), ('unknown', FILE_URL, 502),
            (None, FILE_URL, 502), ('unknown', BLOB_URL, 502),
        ]
        cases.extend(('litterbox', url, 502) for url in (
            'https://evil.example/a.txt', 'http://litter.catbox.moe/a.txt',
            'https://litter.catbox.moe.evil.example/a.txt',
            'https://user@litter.catbox.moe/a.txt', 'https://litter.catbox.moe:443/a.txt',
            'https://litter.catbox.moe/../a.txt', 'https://litter.catbox.moe/a/b.txt',
            FILE_URL + '?redirect=1', FILE_URL + '#fragment',
            'https://litter.catbox.moe/a\nb.txt', 'https://litter.catbox.moe/a\tb.txt',
        ))
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as get:
            for provider, url, status in cases:
                with self.subTest(provider=provider, url=url):
                    with app.app_context():
                        db = get_db()
                        with db:
                            db.execute('''INSERT OR REPLACE INTO shares
                                          (key, type, name, content, url, size, expires, provider)
                                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                       ('00007', 'file', 'test.txt', None, url, 1, self.now + 3600, provider))
                    response = self.client.get('/download/00007')
                    self.assertEqual(response.status_code, status)
                    self.assertNotIn(BLOB_TOKEN.encode(), response.data)
                    if status == 302:
                        self.assertEqual(response.location, FILE_URL)
                    else:
                        self.assertNotIn('Location', response.headers)
                    get.assert_not_called()
        self.post.assert_not_called()

    def test_cleanup_only_deletes_remote_blobs_for_vercel_provider(self):
        rows = [
            ('00007', 'file', 'report.pdf', None, BLOB_URL, 9, self.now - 1, 'vercel'),
            ('00008', 'file', 'test.txt', None, FILE_URL, 1, self.now - 1, 'litterbox'),
            # A misleading URL must not turn a non-Vercel share into a Blob deletion.
            ('00009', 'file', 'test.txt', None, BLOB_URL, 1, self.now - 1, 'litterbox'),
            ('00010', 'file', 'test.txt', None, BLOB_URL, 1, self.now - 1, 'unknown'),
            ('00011', 'text', 'Shared Text', 'expired', None, 7, self.now - 1, None),
            ('00012', 'file', 'live.pdf', None, BLOB_URL, 9, self.now + 3600, 'vercel'),
        ]
        with app.app_context():
            db = get_db()
            with db:
                db.executemany('''INSERT INTO shares (key, type, name, content, url, size, expires, provider)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', rows)
        self.mock_provider()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            result = app.test_cli_runner().invoke(args=['cleanup-shares'])
        self.assertEqual(result.exit_code, 0)
        self.post.assert_called_once()
        self.assertEqual(self.post.call_args.args[0], 'https://vercel.com/api/blob/delete')
        self.assertEqual(self.post.call_args.kwargs['json'], {'urls': [BLOB_URL]})
        with app.app_context():
            remaining = get_db().execute('SELECT key FROM shares').fetchall()
            self.assertEqual([row['key'] for row in remaining], ['00012'])

    def test_private_blob_removed_when_metadata_cannot_be_saved(self):
        url = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32 + '/report.pdf'
        self.mock_provider()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN='vercel_blob_rw_teststore_fakecredential'), \
                patch('flask_app.requests.put') as put, \
                patch('flask_app.save_share', side_effect=sqlite3.OperationalError('database unavailable')):
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': url}
            response = self.client.post('/upload', data={
                'storageProvider': 'vercel', 'file': (BytesIO(b'PDF bytes'), 'report.pdf'),
            })
            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.get_json()['success'])
            self.assertEqual(self.post.call_args.kwargs['json'], {'urls': [url]})

    def test_homepage_brand_and_metadata_use_trusted_canonical(self):
        with patch('flask_app.get_db', side_effect=AssertionError('Public pages must not need a database')):
            response = self.client.get('/', base_url='https://untrusted.example')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('X-Robots-Tag', response.headers)
        html = response.get_data(as_text=True)
        tags = Markup(html).tags
        self.assertIn('<title>AlienXFile - Temporary File &amp; Text Sharing</title>', html)
        self.assertIn('<h1>AlienXFile</h1>', html)
        canonical = next(attrs for tag, attrs in tags if tag == 'link' and attrs.get('rel') == 'canonical')
        self.assertEqual(canonical['href'], 'https://alienxfilev2.onrender.com/')
        metadata = {attrs.get('name') or attrs.get('property'): attrs.get('content')
                    for tag, attrs in tags if tag == 'meta'}
        self.assertIn('AlienXFile', metadata['description'])
        self.assertEqual(metadata['og:url'], canonical['href'])
        self.assertEqual(metadata['robots'], 'index, follow')
        schema = json.loads(re.search(r'<script type="application/ld\+json">\s*(.*?)\s*</script>', html, re.S)[1])
        self.assertEqual(schema['@type'], 'WebSite')
        self.assertEqual(schema['name'], 'AlienXFile')
        self.assertEqual(schema['url'], canonical['href'])

    def test_discovery_routes_include_only_homepage(self):
        with patch('flask_app.get_db', side_effect=AssertionError('Discovery must not enumerate shares')):
            robots = self.client.get('/robots.txt')
            sitemap = self.client.get('/sitemap.xml')
            icon = self.client.get('/static/favicon.svg')
            self.assertEqual(self.client.get('/indexnow-key.txt').status_code, 404)
            with patch.dict(app.config, INDEXNOW_KEY='a' * 32):
                key = self.client.get('/indexnow-key.txt')
        self.assertEqual(robots.status_code, 200)
        self.assertEqual(robots.mimetype, 'text/plain')
        self.assertIn(b'Sitemap: https://alienxfilev2.onrender.com/sitemap.xml', robots.data)
        self.assertNotIn(b'Disallow:', robots.data)
        self.assertEqual(sitemap.status_code, 200)
        self.assertEqual(sitemap.mimetype, 'application/xml')
        root = ElementTree.fromstring(sitemap.data)
        locations = root.findall('{http://www.sitemaps.org/schemas/sitemap/0.9}url/{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
        self.assertEqual([location.text for location in locations], ['https://alienxfilev2.onrender.com/'])
        self.assertEqual(icon.status_code, 200)
        icon.close()
        self.assertEqual(key.status_code, 200)
        self.assertEqual(key.data, b'a' * 32)
        self.assertIn('noindex', key.headers['X-Robots-Tag'])

    def test_google_verification_serves_only_the_exact_file(self):
        filename = 'googled943441d68fdfc65.html'
        with patch('flask_app.get_db', side_effect=AssertionError('Verification must not need a database')):
            response = self.client.get('/' + filename)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/html')
        self.assertEqual(response.data, Path(__file__).with_name(filename).read_bytes())
        self.assertEqual(response.data.strip(), ('google-site-verification: ' + filename).encode())
        response.close()
        self.assertEqual(self.client.get('/README.md').status_code, 404)

    def test_lookup_upload_and_errors_are_not_indexable(self):
        for method, path in (('GET', '/download'), ('GET', '/share/99999'), ('GET', '/qr/99999'),
                             ('GET', '/download/99999'), ('GET', '/missing'), ('GET', '/static/missing'),
                             ('POST', '/'), ('POST', '/upload'), ('POST', '/download')):
            with self.subTest(method=method, path=path):
                response = self.client.open(path, method=method, data={'key': '99999'})
                self.assertIn('noindex', response.headers['X-Robots-Tag'])
                self.assertIn('nofollow', response.headers['X-Robots-Tag'])

    def test_error_pages_offer_explicit_download_form(self):
        for method, path, status in (('GET', '/missing', 404), ('GET', '/share/99999', 404),
                                     ('PUT', '/share/99999', 405), ('GET', '/upload', 405)):
            with self.subTest(method=method, path=path):
                response = self.client.open(path, method=method)
                self.assertEqual(response.status_code, status)
                if path == '/upload':
                    self.assertFalse(response.get_json()['success'])
                else:
                    self.assert_download_form(response)
                if status == 405:
                    self.assertIn('Allow', response.headers)
        with patch('flask_app.get_db', side_effect=sqlite3.OperationalError('private DB path')):
            for path in ('/share/00007', '/download/00007'):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 503)
                self.assertNotIn(b'private DB path', response.data)
                self.assert_download_form(response)
            response = self.client.post('/upload', data={'mode': 'text', 'text': 'note'})
            self.assertEqual(response.status_code, 503)
            self.assertFalse(response.get_json()['success'])
            self.assertNotIn(b'private DB path', response.data)


    def test_preview_endpoint(self):
        self.mock_provider(link='https://litter.catbox.moe/abc123py', status=200)
        response = self.client.post('/upload', data={
            'mode': 'file', 'storageProvider': 'litterbox',
            'file': (BytesIO(b'print("hello")'), 'test.py'), 'expire': '1h',
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        key = response.get_json()['uploads'][0]['key']
        with patch('flask_app.requests.get') as mock_get:
            file_resp = requests.Response()
            file_resp.status_code = 200
            file_resp._content = b'print("hello")'
            file_resp._content_consumed = True
            file_resp.headers['Content-Type'] = 'text/plain'
            mock_get.return_value.__enter__ = lambda s: s
            mock_get.return_value.__exit__ = lambda s, *a: False
            mock_get.return_value = file_resp
            response = self.client.get(f'/api/preview/{key}')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['content'], 'print("hello")')
        self.mock_provider(link='https://litter.catbox.moe/imgpng', status=200)
        response = self.client.post('/upload', data={
            'mode': 'file', 'storageProvider': 'litterbox',
            'file': (BytesIO(b'\x89PNG'), 'photo.png'), 'expire': '1h',
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        key2 = response.get_json()['uploads'][0]['key']
        with patch('flask_app.requests.get') as mock_get:
            file_resp = requests.Response()
            file_resp.status_code = 200
            file_resp._content = b'\x89PNG'
            file_resp._content_consumed = True
            file_resp.headers['Content-Type'] = 'image/png'
            mock_get.return_value.__enter__ = lambda s: s
            mock_get.return_value.__exit__ = lambda s, *a: False
            mock_get.return_value = file_resp
            response = self.client.get(f'/api/preview/{key2}')
            self.assertEqual(response.status_code, 200)
            self.assertIn('image/png', response.content_type)
        response = self.client.get('/api/preview/abc123')
        self.assertEqual(response.status_code, 404)


    def insert_share(self, key, name, provider='vercel', url=None, expires=None,
                     salt=None, iv=None, is_encrypted=0):
        url = url or (BLOB_URL if provider == 'vercel' else FILE_URL)
        with app.app_context():
            db = get_db()
            with db:
                db.execute('''INSERT INTO shares (key, type, name, content, url, size, expires,
                                                  provider, salt, iv, is_encrypted)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (key, 'file', name, None, url, 9, expires or (self.now + 3600),
                            provider, salt, iv, is_encrypted))

    def insert_folder(self, key, name, files, expires=None):
        with app.app_context():
            db = get_db()
            with db:
                db.execute('''INSERT INTO shares (key, type, name, content, url, size, expires,
                                                  provider, salt, iv, is_encrypted)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (key, 'folder', name, json.dumps(files), None, 0,
                            expires or (self.now + 3600), None, None, None, 0))

    def file_response(self, content=b'hello', content_type='text/plain'):
        response = requests.Response()
        response.status_code = 200
        response._content = content
        response._content_consumed = True
        response.headers['Content-Type'] = content_type
        return response

    def redirect_response(self, location, status=302):
        response = requests.Response()
        response.status_code = status
        response.headers['Location'] = location
        response._content = b''
        response._content_consumed = True
        return response

    def fake_dns(self):
        def getaddrinfo(host, *args, **kwargs):
            try:
                ipaddress.ip_address(host)
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (host, 0))]
            except ValueError:
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        return patch('flask_app.socket.getaddrinfo', side_effect=getaddrinfo)

    def test_encrypted_file_preview_is_rejected_before_any_storage_read(self):
        self.insert_share('80001', 'secret.txt', provider='litterbox',
                          salt='c2FsdA==', iv='aXY=', is_encrypted=1)
        with patch('flask_app.requests.get') as mock_get:
            response = self.client.get('/api/preview/80001')
            mock_get.assert_not_called()
        self.assertEqual(response.status_code, 400)
        html = response.get_data(as_text=True)
        self.assertIn('Encrypted shares preview after unlocking.', html)
        self.assertNotIn(FILE_URL, html)
        self.assertNotIn('c2FsdA==', html)
        page = self.client.get('/share/80001')
        self.assertEqual(page.status_code, 200)
        page_html = page.get_data(as_text=True)
        self.assertIn('password-prompt', page_html)
        self.assertNotIn('id="previewContainer"', page_html)

    def test_preview_litterbox_fetch_sends_curl_user_agent(self):
        self.mock_provider(link='https://litter.catbox.moe/abc123py', status=200)
        response = self.client.post('/upload', data={
            'mode': 'file', 'storageProvider': 'litterbox',
            'file': (BytesIO(b'print("hello")'), 'test.py'), 'expire': '1h',
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        key = response.get_json()['uploads'][0]['key']
        file_resp = requests.Response()
        file_resp.status_code = 200
        file_resp._content = b'print("hello")'
        file_resp._content_consumed = True
        file_resp.headers['Content-Type'] = 'text/plain'
        with patch('flask_app.requests.get') as mock_get:
            mock_get.return_value = file_resp
            response = self.client.get(f'/api/preview/{key}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['content'], 'print("hello")')
        self.assertEqual(mock_get.call_args.args[0], 'https://litter.catbox.moe/abc123py')
        self.assertEqual(mock_get.call_args.kwargs['headers']['User-Agent'], 'curl/8.5.0')

    def test_preview_category_is_shared_by_server_and_download_page(self):
        template = Path(__file__).with_name('templates') / 'download.html'
        source = template.read_text(encoding='utf-8')
        self.assertIn('preview_category(share.name)', source)
        self.assertNotIn("previewCat = 'image' if ext in", source)
        names = ['photo.png', 'clip.mp4', 'song.mp3', 'doc.pdf', 'notes.txt',
                 'site.env', '.env', 'repo.gitignore', '.gitignore',
                 'image.dockerfile', 'dockerfile', 'Dockerfile',
                 'rules.makefile', 'makefile', 'Makefile',
                 'archive.zip', 'setup.exe', 'no-extension']
        for index, name in enumerate(names):
            key = f'90{index:03d}'
            self.insert_share(key, name)
            page = self.client.get(f'/share/{key}')
            self.assertEqual(page.status_code, 200, name)
            with self.subTest(name=name):
                html = page.get_data(as_text=True)
                self.assertEqual('id="previewContainer"' in html,
                                 _preview_category(name) is not None)
                self.assertEqual(_preview_category(name),
                                 _preview_category(name.upper()))

    def test_encrypted_decrypt_flow_builds_text_nodes_instead_of_html(self):
        template = Path(__file__).with_name('templates') / 'download.html'
        source = template.read_text(encoding='utf-8')
        section = source[source.index('Feature 6'):source.index('Feature 11')]
        self.assertNotIn('innerHTML', section)
        self.assertIn('heading.textContent = filename;', section)
        self.assertIn('doneHeading.textContent = filename;', section)
        self.assertIn('pre.textContent = text;', section)
        self.assertIn('link.download = filename;', section)
        self.insert_share('80002', '<img src=x onerror=alert(1)>.txt', provider='litterbox',
                          salt='c2FsdA==', iv='aXY=', is_encrypted=1)
        page = self.client.get('/share/80002')
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn('data-filename="&lt;img src=x onerror=alert(1)&gt;.txt"', html)
        self.assertNotIn('<img src=x onerror=alert(1)>', html)
        self.assertNotIn('id="previewContainer"', html)

    @unittest.skipUnless(shutil.which('node'), 'node is required to execute renderMarkdown')
    def test_markdown_links_only_anchor_allowlisted_schemes(self):
        template = Path(__file__).with_name('templates') / 'download.html'
        source = template.read_text(encoding='utf-8')
        start = source.index('function renderMarkdown')
        end = source.index('// Code file preview loader')
        section = source[start:end]
        self.assertIn('return html;', section)
        self.assertIn('rel="noopener noreferrer"', section)
        self.assertNotIn("'<a href=\"$2\"", section)
        payloads = [
            '[click](javascript:alert(1))',
            '[click](JAVASCRIPT:alert(1))',
            '[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
            '[click](vbscript:msgbox(1))',
            '[click](java\tscript:alert(1))',
            '[click](\tjavascript:alert(1))',
            '[click](https://example.com/page?a=1&b=2)',
            '[click](mailto:someone@example.com)',
            '[click](/relative/path)',
            '[click](#section)',
            '<script>alert(1)</script> [ok](https://example.com)',
            '# Ctrl **b** *i*',
        ]
        blocked = payloads[:6]
        node_script = (
            "const fs = require('fs');\n"
            "const html = fs.readFileSync(process.argv[1], 'utf8');\n"
            "const start = html.indexOf('function renderMarkdown');\n"
            "const end = html.indexOf('// Code file preview loader');\n"
            "const inputs = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
            "if (start < 0 || end <= start) process.exit(2);\n"
            "eval(html.slice(start, end));\n"
            "process.stdout.write(JSON.stringify(inputs.map(renderMarkdown)));\n"
        )
        with tempfile.TemporaryDirectory(prefix='alienx-node-') as directory:
            inputs = Path(directory) / 'inputs.json'
            inputs.write_text(json.dumps(payloads), encoding='utf-8')
            result = subprocess.run(['node', '-e', node_script, str(template), str(inputs)],
                                    capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = json.loads(result.stdout)
        self.assertEqual(len(outputs), len(payloads))
        for payload, output in zip(blocked, outputs[:len(blocked)]):
            with self.subTest(payload=payload):
                # Rejected schemes must survive verbatim as plain text: no anchor,
                # no href attribute, and never diverted into a code-block render.
                self.assertEqual(output, payload)
                self.assertNotIn('<a ', output)
                self.assertNotIn('href=', output)
                self.assertNotIn('<pre><code>', output)
        self.assertIn('<a href="https://example.com/page?a=1&amp;b=2" target="_blank" '
                      'rel="noopener noreferrer">click</a>', outputs[6])
        self.assertIn('<a href="mailto:someone@example.com"', outputs[7])
        self.assertIn('<a href="/relative/path"', outputs[8])
        self.assertIn('<a href="#section"', outputs[9])
        self.assertNotIn('<script>', outputs[10])
        self.assertIn('&lt;script&gt;', outputs[10])
        self.assertIn('<a href="https://example.com"', outputs[10])
        # Control payload: proves the extraction executed the real markdown parser
        # (headers/bold/emitter) instead of passing input through untouched.
        self.assertEqual(outputs[11], '<h1>Ctrl <strong>b</strong> <em>i</em></h1>')

    def test_preview_media_markup_lightbox_and_zip_omission(self):
        cases = {
            '92001': ('photo.png', ['id="previewContainer"',
                                    '<img class="preview-media preview-image"',
                                    'id="previewImage"', 'src="/api/preview/92001"',
                                    'title="Click to zoom"']),
            '92002': ('clip.mp4', ['<video class="preview-media preview-video" controls',
                                   '<source src="/api/preview/92002">']),
            '92003': ('song.mp3', ['<audio class="preview-audio" controls',
                                   '<source src="/api/preview/92003">']),
            '92004': ('doc.pdf', ['<embed class="preview-pdf" src="/api/preview/92004"',
                                  'type="application/pdf"']),
            '92005': ('notes.py', ['id="previewCodeContent"', 'id="previewCopyBtn"',
                                   'id="codeFontUp"', 'id="codeFontDown"',
                                   'id="previewTruncation"']),
            '92006': ('archive.zip', None),
        }
        pages = {}
        for key, (name, needles) in cases.items():
            self.insert_share(key, name)
            response = self.client.get(f'/share/{key}')
            self.assertEqual(response.status_code, 200, name)
            pages[key] = response.get_data(as_text=True)
            with self.subTest(name=name):
                if needles is None:
                    self.assertNotIn('id="previewContainer"', pages[key])
                    self.assertNotIn('id="previewCodeContent"', pages[key])
                else:
                    for needle in needles:
                        self.assertIn(needle, pages[key])
        image = pages['92001']
        for needle in ('id="lightbox"', 'id="lightboxImg"', 'id="lightboxViewport"',
                       'id="zoomIn"', 'id="zoomOut"', 'id="zoomReset"', 'id="lightboxClose"',
                       'if (!lightbox || !previewImg) return;'):
            self.assertIn(needle, image)
        self.assertNotIn('onclick=', image)
        for key in ('92002', '92003', '92004', '92005', '92006'):
            self.assertNotIn('id="previewImage"', pages[key])

    def test_preview_endpoint_serves_code_names_and_rejects_zip(self):
        with patch('flask_app.requests.get') as mock_get:
            for key, name, content in (('93001', '.env', 'SECRET=1\n'),
                                       ('93002', 'Dockerfile', 'FROM alpine\n')):
                self.insert_share(key, name, provider='litterbox')
                file_resp = requests.Response()
                file_resp.status_code = 200
                file_resp._content = content.encode('utf-8')
                file_resp._content_consumed = True
                file_resp.headers['Content-Type'] = 'text/plain'
                mock_get.return_value = file_resp
                response = self.client.get(f'/api/preview/{key}')
                with self.subTest(name=name):
                    self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                    self.assertEqual(response.get_json()['content'], content)
            self.assertTrue(mock_get.called)
            mock_get.reset_mock()
            self.insert_share('93003', 'archive.zip', provider='litterbox')
            response = self.client.get('/api/preview/93003')
            self.assertEqual(response.status_code, 400)
            self.assertIn('No preview available for this file type.',
                          response.get_data(as_text=True))
            mock_get.assert_not_called()

    def test_upload_litterbox_sanitizes_hostile_names(self):
        cases = [
            ('../../etc/passwd.txt', 'etc_passwd.txt'),
            ('/etc/shadow.txt', 'etc_shadow.txt'),
            ('..\\..\\Windows\\evil.txt', 'Windowsevil.txt'),
            ('bad\x00name.txt', 'badname.txt'),
            ('line\r\nbreak.txt', 'line_break.txt'),
            ('qu"ote\'.txt', 'quote.txt'),
            ('   ', 'Shared File'),
            ('.....', 'Shared File'),
            ('café.txt', 'cafe.txt'),
            ('a' * 300 + '.txt', 'a' * 255),
        ]
        for raw, expected in cases:
            response = self.client.post('/upload-litterbox', json={
                'url': FILE_URL, 'name': raw, 'size': 5, 'expire': '1h',
            })
            with self.subTest(name=raw):
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                stored = response.get_json()['uploads'][0]['name']
                self.assertEqual(stored, expected)
                if stored != 'Shared File':
                    self.assertRegex(stored, r'^[A-Za-z0-9_.-]+$')
                self.assertLessEqual(len(stored), 255)
                self.assertFalse(stored.startswith('.'))
        for raw in ('evil.exe', '../evil.exe'):
            response = self.client.post('/upload-litterbox', json={
                'url': FILE_URL, 'name': raw, 'size': 5, 'expire': '1h',
            })
            with self.subTest(banned=raw):
                self.assertEqual(response.status_code, 400)
                self.assertIn('blocked', response.get_json()['error'])

    def test_bulk_download_sanitizes_zip_entries_and_resolves_collisions(self):
        hostile = [
            ('70001', '../a.txt', b'first', 'a.txt'),
            ('70002', '..\\a.txt', b'second', 'a-2.txt'),
            ('70003', 'a.txt', b'third', 'a-3.txt'),
            ('70004', 'bad\x00name.txt', b'fourth', 'badname.txt'),
            ('70005', 'qu"ote\r\n.txt', b'fifth', 'quote_.txt'),
        ]
        for key, name, _, _ in hostile:
            self.insert_share(key, name, provider='litterbox')
        with patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(content) for _, _, content, _ in hostile]
            response = self.client.post('/bulk-download', json={'keys': [key for key, *_ in hostile]})
        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(BytesIO(response.data)) as archive:
            names = archive.namelist()
            self.assertEqual(names, [expected for *_, expected in hostile])
            for _, _, content, expected in hostile:
                self.assertEqual(archive.read(expected), content)
            for name in names:
                self.assertRegex(name, r'^[A-Za-z0-9_.-]+$')
                self.assertNotIn('..', name)
        for call in mock_get.call_args_list:
            self.assertEqual(call.args[0], FILE_URL)

    def test_bulk_download_skips_unvalidated_storage_urls(self):
        self.insert_share('70101', 'trap.txt', provider='litterbox',
                          url='https://evil.example.com/steal')
        self.insert_share('70102', 'trap2.txt', provider='vercel',
                          url='https://evil.example.com/token')
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            response = self.client.post('/bulk-download', json={'keys': ['70101', '70102']})
            mock_get.assert_not_called()
        self.assertEqual(response.status_code, 404)
        self.assertIn('No valid files found', response.get_json()['error'])

    def test_folder_routes_revalidate_urls_and_zip_is_collision_safe(self):
        files = [
            {'name': '../a.txt', 'url': FILE_URL, 'provider': 'litterbox', 'size': 6},
            {'name': 'a.txt', 'url': 'https://litter.catbox.moe/other456.txt',
             'provider': 'litterbox', 'size': 7},
            {'name': 'evil.txt', 'url': 'https://evil.example.com/secret',
             'provider': 'litterbox', 'size': 1},
            {'name': 'trap.txt', 'url': 'https://evil.example.com/blob-token-harvest',
             'provider': 'vercel', 'size': 1},
            {'name': '../../doc.pdf', 'url': BLOB_URL, 'provider': 'vercel', 'size': 9},
        ]
        self.insert_folder('71001', 'bad"name', files)
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(b'first!'),
                                    self.file_response(b'second!'),
                                    self.file_response(b'%PDF-1.4', 'application/pdf')]
            response = self.client.get('/download-folder-zip/71001')
            self.assertEqual(response.status_code, 200)
            self.assertEqual([call.args[0] for call in mock_get.call_args_list],
                             [FILE_URL, 'https://litter.catbox.moe/other456.txt', BLOB_URL])
            self.assertRegex(response.headers['Content-Disposition'],
                             r'^attachment; filename="?badname\.zip"?$')
            with zipfile.ZipFile(BytesIO(response.data)) as archive:
                self.assertEqual(archive.namelist(), ['a.txt', 'a-2.txt', 'doc.pdf'])
                self.assertEqual(archive.read('a.txt'), b'first!')
                self.assertEqual(archive.read('a-2.txt'), b'second!')
                self.assertEqual(archive.read('doc.pdf'), b'%PDF-1.4')
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            for index, fragment in ((2, 'Invalid storage link.'), (3, 'Invalid storage link.')):
                response = self.client.get(f'/download-folder/71001/{index}')
                with self.subTest(index=index):
                    self.assertEqual(response.status_code, 502)
                    self.assertIn(fragment, response.get_data(as_text=True))
            mock_get.assert_not_called()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.return_value = self.file_response(b'%PDF-1.4', 'application/pdf')
            response = self.client.get('/download-folder/71001/4')
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            self.assertEqual(mock_get.call_args.args[0], BLOB_URL)
            self.assertIn('Bearer ', mock_get.call_args.kwargs['headers']['Authorization'])
            self.assertRegex(response.headers['Content-Disposition'],
                             r'^attachment; filename="?doc\.pdf"?$')

    def test_url_meta_rejects_private_and_cross_scheme_redirects(self):
        with self.fake_dns(), patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.redirect_response('http://169.254.169.254/latest/meta-data/')]
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/page'})
            self.assertEqual(response.status_code, 403)
            self.assertIn('private/internal', response.get_json()['error'])
            self.assertEqual(mock_get.call_count, 1)
            mock_get.reset_mock()
            mock_get.side_effect = [self.redirect_response('http://127.0.0.1:8080/admin')]
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/page'})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(mock_get.call_count, 1)
            mock_get.reset_mock()
            mock_get.side_effect = [self.redirect_response('javascript:alert(1)')]
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/page'})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.get_json()['error'], 'Provide a valid URL.')
            self.assertEqual(mock_get.call_count, 1)
            mock_get.reset_mock()
            response = self.client.post('/api/url-meta', json={'url': 'http://10.0.0.5/x'})
            self.assertEqual(response.status_code, 403)
            mock_get.assert_not_called()

    def test_url_meta_follows_bounded_redirect_hops(self):
        with self.fake_dns(), patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [
                self.redirect_response('https://public.example/b'),
                self.redirect_response('https://public.example/c'),
                self.redirect_response('https://public.example/d'),
                self.redirect_response('https://public.example/e'),
            ]
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/a'})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.get_json()['error'], 'Too many redirects.')
            self.assertEqual(mock_get.call_count, 4)
            mock_get.reset_mock()
            mock_get.side_effect = [
                self.redirect_response('https://public.example/b'),
                self.redirect_response('https://public.example/c'),
                self.redirect_response('https://public.example/d'),
                self.file_response(b'<title>Three hops ok</title>'),
            ]
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/a'})
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            self.assertEqual(response.get_json()['title'], 'Three hops ok')
            self.assertEqual(mock_get.call_count, 4)
            mock_get.reset_mock()
            mock_get.side_effect = [
                self.redirect_response('/meta'),
                self.file_response(b'<title>Relative ok</title>'),
            ]
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/page'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['title'], 'Relative ok')
            self.assertEqual(mock_get.call_args_list[1].args[0], 'https://public.example/meta')
            mock_get.reset_mock()
            mock_get.side_effect = None
            mock_get.return_value = requests.Response()
            mock_get.return_value.status_code = 500
            mock_get.return_value._content = b'boom'
            mock_get.return_value._content_consumed = True
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/page'})
            self.assertEqual(response.status_code, 402)
            self.assertEqual(response.get_json()['error'], 'Could not fetch URL (HTTP 500).')

    def test_url_meta_rate_limit_is_separate_and_persistent(self):
        with self.fake_dns(), patch.dict(app.config, URL_META_RATE_LIMIT=2), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = lambda *a, **k: self.file_response(b'<title>ok</title>')
            for status in (200, 200, 429):
                response = self.client.post('/api/url-meta', json={'url': 'https://public.example/'})
                self.assertEqual(response.status_code, status)
            self.assertIn(int(response.headers['Retry-After']), (60, 61))
            self.assertEqual(self.client.get('/share/99999').status_code, 404)
            self.clock.return_value = self.now + 61
            response = self.client.post('/api/url-meta', json={'url': 'https://public.example/'})
            self.assertEqual(response.status_code, 200)

    def test_preview_rate_limit_is_separate_from_lookup_bucket(self):
        self.insert_share('72001', 'notes.txt', provider='litterbox')
        with patch.dict(app.config, PREVIEW_RATE_LIMIT=2), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = lambda *a, **k: self.file_response(b'hello')
            for status in (200, 200, 429):
                response = self.client.get('/api/preview/72001')
                self.assertEqual(response.status_code, status)
            self.assertIn(int(response.headers['Retry-After']), (60, 61))
            self.assertEqual(self.client.get('/share/72001').status_code, 200)
            self.assertEqual(self.client.post('/download', data={'key': '72001'}).status_code, 303)
            self.clock.return_value = self.now + 61
            self.assertEqual(self.client.get('/api/preview/72001').status_code, 200)

    # ══════════════════════════════════════════════════════════════════════
    # Multi-file selections share ONE code (File tab posts one batch request)
    # ══════════════════════════════════════════════════════════════════════

    def batch_upload(self, files, **extra):
        """Post a multi-file selection the way the File tab now does: one
        request to /upload-folder, with the Vercel PUT mocked per file."""
        payload = {'expire': extra.pop('expire', '1h')}
        payload.update(extra)
        payload['file'] = [(BytesIO(body), name) for name, body in files]
        urls = ['https://teststore.private.blob.vercel-storage.com/shares/'
                f'{index:032x}/blob{index}' for index in range(len(files))]
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.side_effect = [{'url': url} for url in urls]
            response = self.client.post('/upload-folder', data=payload)
        return response

    def test_multi_file_selection_creates_one_share_for_the_whole_batch(self):
        files = [('photo1.jpg', b'JPEG-ONE'), ('photo2.png', b'PNG-TWO'),
                 ('document.pdf', b'%PDF-1.4 batch'), ('video.mp4', b'MP4-THREE'),
                 ('notes.txt', b'plain notes')]
        response = self.batch_upload(files, expire='12h')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(result['success'])
        self.assertEqual(result['errors'], [])
        share, = result['uploads']
        # ONE code for the whole batch, one expiry, one row in the database.
        with app.app_context():
            rows = get_db().execute('SELECT key, type, expires FROM shares').fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['key'], share['key'])
        self.assertEqual(share['type'], 'folder')
        self.assertEqual(share['name'], '5 files')
        self.assertIsNone(share['storageProvider'])
        self.assertEqual(share['size'], sum(len(body) for _, body in files))
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 43200)
        # The share holds every file from the selection, in order, with sizes.
        self.assertEqual([f['name'] for f in share['files']], [name for name, _ in files])
        self.assertEqual([f['size'] for f in share['files']],
                         [len(body) for _, body in files])
        self.assertEqual({f['provider'] for f in share['files']}, {'vercel'})
        # The share page represents the batch: a listing, per-file download
        # links, and the "Download All as ZIP" button. No single-file preview.
        page = self.client.get(f'/share/{share["key"]}')
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn('5 files', html)
        self.assertIn('Download All as ZIP', html)
        self.assertNotIn('id="previewContainer"', html)
        for index, (name, _) in enumerate(files):
            with self.subTest(index=index, name=name):
                self.assertIn(f'/download-folder/{share["key"]}/{index}', html)
                self.assertIn(name, html)

    def test_batch_share_downloads_each_file_and_one_safe_zip(self):
        files = [('a.txt', b'first-a'), ('../a.txt', b'second-a'),
                 ('sub/notes.txt', b'nested-notes'), ('../../etc/passwd.txt', b'escape')]
        response = self.batch_upload(files)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        share, = result['uploads']
        # Hostile names are sanitized before storage: no separators, no traversal.
        stored = [f['name'] for f in share['files']]
        self.assertEqual(stored, ['a.txt', 'a.txt', 'sub_notes.txt', 'etc_passwd.txt'])
        for name in stored:
            self.assertNotIn('/', name)
            self.assertNotIn('\\', name)
        self.assertFalse(any(name.startswith('.') for name in stored))
        # Individual downloads stream exactly one file each.
        for index, (_, body) in enumerate(files):
            with self.subTest(index=index):
                with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                        patch('flask_app.requests.get') as mock_get:
                    mock_get.return_value = self.file_response(body)
                    single = self.client.get(f'/download-folder/{share["key"]}/{index}')
                self.assertEqual(single.status_code, 200, single.get_data(as_text=True))
                self.assertEqual(single.data, body)
                self.assertIn('attachment', single.headers['Content-Disposition'])
        # The ZIP holds every file once, under safe names, without overwrites.
        contents = [b'first-a', b'second-a', b'nested-notes', b'escape']
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(body) for body in contents]
            archive_response = self.client.get(f'/download-folder-zip/{share["key"]}')
        self.assertEqual(archive_response.status_code, 200)
        self.assertRegex(archive_response.headers['Content-Disposition'],
                         r'^attachment; filename="?4_files\.zip"?$')
        requested = [call.args[0] for call in mock_get.call_args_list]
        self.assertEqual(requested, [f['url'] for f in share['files']])
        with zipfile.ZipFile(BytesIO(archive_response.data)) as archive:
            self.assertEqual(archive.namelist(),
                             ['a.txt', 'a-2.txt', 'sub_notes.txt', 'etc_passwd.txt'])
            self.assertEqual(archive.read('a.txt'), b'first-a')
            self.assertEqual(archive.read('a-2.txt'), b'second-a')
            self.assertEqual(archive.read('sub_notes.txt'), b'nested-notes')
            self.assertEqual(archive.read('etc_passwd.txt'), b'escape')
            self.assertEqual(len(set(archive.namelist())), 4)

    def test_folder_selection_still_creates_one_share_with_flattened_paths(self):
        files = [('holiday/notes.txt', b'n1'), ('holiday/photo.jpg', b'p1')]
        response = self.batch_upload(files, expire='72h')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(result['success'])
        share, = result['uploads']
        self.assertEqual(share['type'], 'folder')
        self.assertEqual(share['name'], '2 files')
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 259200)
        self.assertEqual([f['name'] for f in share['files']],
                         ['holiday_notes.txt', 'holiday_photo.jpg'])
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 1)

    def test_single_file_upload_keeps_file_share_preview_and_direct_download(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            response = self.client.post('/upload', data={
                'mode': 'file', 'storageProvider': 'vercel', 'expire': '1h',
                'file': (BytesIO(b'just one file'), 'solo.txt'),
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(result['success'])
        self.assertEqual(result['errors'], [])
        share, = result['uploads']
        self.assertEqual(share['type'], 'file')
        self.assertEqual(share['name'], 'solo.txt')
        self.assertTrue(share['page_url'].endswith(f'/share/{share["key"]}'))
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 1)
        # Direct link still streams the single file.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.return_value = self.file_response(b'just one file')
            direct = self.client.get(f'/download/{share["key"]}')
        self.assertEqual(direct.status_code, 200)
        self.assertEqual(direct.data, b'just one file')
        # Preview still works for the single file.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.return_value = self.file_response(b'print(1)', 'text/plain')
            preview = self.client.get(f'/api/preview/{share["key"]}')
        self.assertEqual(preview.status_code, 200)
        self.assertIn(b'print(1)', preview.data)
        page = self.client.get(f'/share/{share["key"]}')
        self.assertIn('id="previewContainer"', page.get_data(as_text=True))

    def test_single_file_encryption_still_protects_share_content(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            response = self.client.post('/upload', data={
                'mode': 'file', 'storageProvider': 'vercel', 'expire': '1h',
                'isEncrypted': '1', 'salt': 'c2FsdA==', 'iv': 'aXY=',
                'file': (BytesIO(b'ciphertext-bytes'), 'secret.txt'),
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        share, = response.get_json()['uploads']
        self.assertTrue(share['is_encrypted'])
        page = self.client.get(f'/share/{share["key"]}')
        html = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn('password-prompt', html)
        self.assertNotIn('id="previewContainer"', html)
        # Ciphertext is never proxied by the preview endpoint.
        with patch('flask_app.requests.get') as mock_get:
            preview = self.client.get(f'/api/preview/{share["key"]}')
            mock_get.assert_not_called()
        self.assertEqual(preview.status_code, 400)

    def efm1_fields(self, **overrides):
        """Valid EFM1 form fields: 16-byte salt, 12-byte manifest IV, >=32-byte
        manifest ciphertext (structure only - the server cannot verify it)."""
        fields = {
            'isEncrypted': '1',
            'salt': base64.b64encode(bytes(range(16))).decode(),
            'iv': base64.b64encode(bytes(range(12, 24))).decode(),
            'manifest': base64.b64encode(b'M' * 64).decode(),
        }
        fields.update(overrides)
        return fields

    def test_encrypted_batch_upload_validates_parameters_before_any_storage(self):
        valid = self.efm1_fields()
        missing_manifest = dict(valid)
        missing_manifest.pop('manifest')
        cases = [
            ({'isEncrypted': '1'}, 'Encryption parameters missing.'),
            ({'salt': valid['salt']}, 'Encryption parameters provided without the isEncrypted flag.'),
            ({'iv': valid['iv'], 'manifest': valid['manifest']},
             'Encryption parameters provided without the isEncrypted flag.'),
            (missing_manifest, 'Encryption parameters missing.'),
            (self.efm1_fields(salt='%%%not-base64%%%'), 'Encryption parameters must be valid base64.'),
            (self.efm1_fields(salt=base64.b64encode(b'short').decode()),
             'Encryption salt must be 16 bytes.'),
            (self.efm1_fields(iv=base64.b64encode(b'0123456789a').decode()),
             'Encryption IV must be 12 bytes.'),
            (self.efm1_fields(manifest=base64.b64encode(b'tiny').decode()),
             'Encryption manifest is invalid.'),
            (self.efm1_fields(salt=base64.b64encode(b'x' * 32).decode()),
             'Encryption parameters are too long.'),
            (self.efm1_fields(manifest='A' * (((131072 + 2) // 3) * 4 + 8)),
             'Encryption parameters are too long.'),
        ]
        files = [(b'one', 'a.txt'), (b'two', 'b.txt')]
        for fields, message in cases:
            with self.subTest(error=message):
                payload = [(BytesIO(body), name) for body, name in files]
                with patch('flask_app.requests.put') as put:
                    response = self.client.post('/upload-folder', data={
                        'expire': '1h', **fields, 'file': payload,
                    })
                self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
                body = response.get_json()
                self.assertFalse(body['success'])
                self.assertEqual(body['uploads'], [])
                self.assertEqual(body['error'], message)
                # Validation runs before any storage call or database write.
                put.assert_not_called()
                with app.app_context():
                    count = get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0]
                self.assertEqual(count, 0)
                self.post.assert_not_called()

    def test_encrypted_batch_upload_creates_authenticated_share_without_leaks(self):
        fields = self.efm1_fields()
        files = [('secret one.txt', b'AAAA-cipher'), ('nested/secret two.bin', b'BB-cipher')]
        urls = ['https://teststore.private.blob.vercel-storage.com/shares/'
                f'{index:032x}/blob{index}' for index in range(len(files))]
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.side_effect = [
                {'url': url} for url in urls]
            response = self.client.post('/upload-folder', data={
                'expire': '1h', **fields,
                'file': [(BytesIO(body), name) for name, body in files],
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(result['success'])
        self.assertEqual(result['errors'], [])
        share, = result['uploads']
        self.assertEqual(share['type'], 'folder')
        self.assertEqual(share['name'], '2 files')
        self.assertTrue(share['is_encrypted'])
        # The sender's own result panel keeps the real (sanitized) names.
        self.assertEqual([f['name'] for f in share['files']],
                         ['secret_one.txt', 'nested_secret_two.bin'])
        # Encrypted batches store neutral object names: storage paths never
        # echo a filename a password-less caller could read.
        pathnames = [call.kwargs['params']['pathname'] for call in put.call_args_list]
        self.assertEqual([p.rsplit('/', 1)[-1] for p in pathnames],
                         ['file-0.bin', 'file-1.bin'])
        for pathname in pathnames:
            self.assertNotIn('secret', pathname)
        # EFM1 envelope in the row: authenticated manifest + serving table.
        with app.app_context():
            row = get_db().execute('SELECT * FROM shares WHERE key = ?',
                                   (share['key'],)).fetchone()
        self.assertEqual(row['is_encrypted'], 1)
        self.assertEqual(row['salt'], fields['salt'])
        self.assertEqual(row['iv'], fields['iv'])
        content = json.loads(row['content'])
        self.assertEqual(content['enc'], 1)
        self.assertEqual(content['v'], 1)
        self.assertEqual(content['cipher'], 'AES-GCM')
        self.assertEqual(content['kdf'], {'name': 'PBKDF2', 'iterations': 100000,
                                          'hash': 'SHA-256'})
        self.assertEqual(content['manifest'], {'iv': fields['iv'], 'data': fields['manifest']})
        self.assertEqual([f['name'] for f in content['files']],
                         ['secret_one.txt', 'nested_secret_two.bin'])
        # The page carries only ciphertext: manifest blob, count, salt, IV and
        # the neutral download endpoints - never names or storage URLs.
        page = self.client.get(f'/share/{share["key"]}')
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn('password-prompt', html)
        self.assertIn(f'data-manifest="{fields["manifest"]}"', html)
        self.assertIn(f'data-iv="{fields["iv"]}"', html)
        self.assertIn(f'data-salt="{fields["salt"]}"', html)
        self.assertIn('data-count="2"', html)
        self.assertIn(f'data-folder-base="/download-folder/{share["key"]}/0"', html)
        self.assertIn(f'data-folder-bundle="/download-folder-cipher/{share["key"]}"', html)
        self.assertNotIn('secret', html)
        self.assertNotIn('teststore.private.blob.vercel-storage.com', html)
        self.assertNotIn('Download All as ZIP', html)
        self.assertNotIn(f'href="/download-folder/{share["key"]}/', html)
        # The preview endpoint never fetches storage for a folder share at all.
        with patch('flask_app.requests.get') as mock_get:
            preview = self.client.get(f'/api/preview/{share["key"]}')
            mock_get.assert_not_called()
        self.assertEqual(preview.status_code, 404)

    def test_encrypted_batch_upload_is_all_or_nothing_on_any_failure(self):
        fields = self.efm1_fields()
        # One accepted file plus one banned extension: the batch must abort,
        # drop the already-stored blob and create no share at all.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put, \
                patch('flask_app.delete_blobs') as delete:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            response = self.client.post('/upload-folder', data={
                'expire': '1h', **fields,
                'file': [(BytesIO(b'ok'), 'a.txt'), (BytesIO(b'bad'), 'evil.exe')],
            })
        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        self.assertIn('evil.exe: This file extension is blocked.',
                      response.get_json()['error'])
        self.assertEqual(response.get_json()['uploads'], [])
        self.assertEqual(put.call_count, 1)
        delete.assert_called_once_with([BLOB_URL])
        with app.app_context():
            count = get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0]
        self.assertEqual(count, 0)
        # Share-creation failure (custom code taken) also cleans up the blobs.
        self.insert_share('taken1', 'existing.txt')
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put, \
                patch('flask_app.delete_blobs') as delete:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            response = self.client.post('/upload-folder', data={
                'expire': '1h', 'customKey': 'taken1', **fields,
                'file': [(BytesIO(b'ok'), 'a.txt')],
            })
        self.assertEqual(response.status_code, 409, response.get_data(as_text=True))
        delete.assert_called_once_with([BLOB_URL])
        with app.app_context():
            count = get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0]
        self.assertEqual(count, 1)
        # A cleanup failure is logged without secrets and still creates no share.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put, \
                patch('flask_app.delete_blobs',
                      side_effect=requests.HTTPError('Private storage cleanup failed.')):
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            with self.assertLogs('flask_app', level='WARNING') as logged:
                response = self.client.post('/upload-folder', data={
                    'expire': '1h', **fields,
                    'file': [(BytesIO(b'ok'), 'a.txt'), (BytesIO(b'bad'), 'evil.exe')],
                })
        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        warning = '\n'.join(logged.output)
        self.assertIn('Encrypted batch blob cleanup deferred (HTTPError); 1 object(s)', warning)
        self.assertNotIn(BLOB_URL, warning)
        self.assertNotIn('private.blob', warning)
        self.assertNotIn('evil.exe', warning)
        with app.app_context():
            count = get_db().execute(
                "SELECT COUNT(*) FROM shares WHERE name LIKE '%files%'").fetchone()[0]
        self.assertEqual(count, 0)

    def insert_encrypted_folder(self, key, files, expires=None, content=None):
        """Encrypted folder row with the EFM1 envelope. `files` is the stored
        serving table (names/URLs the server fetches but never explains)."""
        salt = base64.b64encode(bytes(range(16))).decode()
        iv = base64.b64encode(bytes(range(12, 24))).decode()
        manifest = base64.b64encode(b'M' * 64).decode()
        body = content if content is not None else json.dumps({
            'enc': 1, 'v': 1,
            'kdf': {'name': 'PBKDF2', 'iterations': 100000, 'hash': 'SHA-256'},
            'cipher': 'AES-GCM',
            'manifest': {'iv': iv, 'data': manifest},
            'files': files,
        })
        with app.app_context():
            db = get_db()
            with db:
                db.execute('''INSERT INTO shares (key, type, name, content, url, size, expires,
                                                  provider, salt, iv, is_encrypted)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (key, 'folder', f'{len(files)} files', body, None, 0,
                            expires or (self.now + 3600), None, salt, iv, 1))
        return {'salt': salt, 'iv': iv, 'manifest': manifest}

    def test_encrypted_folder_routes_serve_ciphertext_only(self):
        ciphertext = [b'ENCRYPTED-ONE-0123456789', b'ENCRYPTED-TWO-9876543210']
        files = [
            {'name': 'alpha secret.txt', 'url': FILE_URL, 'provider': 'litterbox',
             'size': len(ciphertext[0])},
            {'name': 'beta secret.bin', 'url': FILE_URL + 'x', 'provider': 'litterbox',
             'size': len(ciphertext[1])},
        ]
        meta = self.insert_encrypted_folder('63001', files)
        # A single file streams ciphertext proxied (never a redirect) under a
        # neutral name that leaks nothing about the stored filename.
        with patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(body) for body in ciphertext]
            single = self.client.get('/download-folder/63001/0')
        self.assertEqual(single.status_code, 200, single.get_data(as_text=True))
        self.assertEqual(single.data, ciphertext[0])
        disposition = single.headers['Content-Disposition']
        self.assertIn('attachment', disposition)
        self.assertIn('file-0', disposition)
        self.assertNotIn('alpha', disposition)
        self.assertNotIn('secret', disposition)
        self.assertTrue(mock_get.call_args.kwargs.get('allow_redirects') is False)
        out_of_range = self.client.get('/download-folder/63001/2')
        self.assertEqual(out_of_range.status_code, 404)
        # The server refuses to build an archive it cannot decrypt.
        with patch('flask_app.requests.get') as mock_get:
            zip_response = self.client.get('/download-folder-zip/63001')
        self.assertEqual(zip_response.status_code, 400)
        self.assertIn('password-protected', zip_response.get_data(as_text=True))
        mock_get.assert_not_called()
        # One framed bundle: magic + count + (length-prefixed) ciphertext frames.
        with patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(body) for body in ciphertext]
            bundle = self.client.get('/download-folder-cipher/63001')
        self.assertEqual(bundle.status_code, 200, bundle.get_data(as_text=True))
        self.assertEqual(bundle.headers['Cache-Control'], 'no-store')
        body = bundle.data
        self.assertEqual(body[:5], b'AXFC1')
        count = int.from_bytes(body[5:9], 'little')
        self.assertEqual(count, 2)
        offset = 9
        frames = []
        for _ in range(count):
            length = int.from_bytes(body[offset:offset + 4], 'little')
            offset += 4
            frames.append(body[offset:offset + length])
            offset += length
        self.assertEqual(offset, len(body))
        self.assertEqual(frames, ciphertext)
        self.assertEqual(int(bundle.headers['Content-Length']), len(body))
        # Names, manifest and count stay server-side only.
        self.assertNotIn(b'alpha', body)
        self.assertNotIn(meta['manifest'].encode(), body)
        # A plaintext folder never uses the cipher route.
        self.insert_folder('63002', '1 file',
                           [{'name': 'plain.txt', 'url': FILE_URL,
                             'provider': 'litterbox', 'size': 1}])
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            plain_bundle = self.client.get('/download-folder-cipher/63002')
        self.assertEqual(plain_bundle.status_code, 400)
        self.assertIn('not password-protected', plain_bundle.get_data(as_text=True))

    def test_folder_cipher_shares_the_lookup_rate_bucket(self):
        files = [{'name': 'a.txt', 'url': FILE_URL, 'provider': 'litterbox', 'size': 1}]
        self.insert_encrypted_folder('63010', files)
        with patch.dict(app.config, LOOKUP_RATE_LIMIT=3), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.return_value = self.file_response(b'ENCRYPTED-ONE-0123456789')
            responses = [self.client.get('/download-folder-cipher/63010'),
                         self.client.get('/download-folder/63010/0'),
                         self.client.get('/download-folder-zip/63010'),
                         self.client.get('/download-folder-cipher/63010')]
            statuses = [response.status_code for response in responses]
            # Closing releases the one-at-a-time bundle slot the cipher
            # responses acquired; tests must not leak it to each other.
            for response in responses:
                response.close()
        # The first three consume the shared lookup allowance; the fourth is 429.
        self.assertEqual(statuses, [200, 200, 400, 429])

    def test_cipher_bundle_streams_byte_identical_frames(self):
        """The bundle is served as a generator of the already-fetched chunks:
        byte-identical wire format and Content-Length, but the view never
        materializes the whole bundle as one bytes/bytearray object. The second
        frame is >64 KB so multi-chunk frames are covered too."""
        ciphertext = [b'ENCRYPTED-ONE-0123456789',
                      bytes(range(256)) * 274]  # 70_144 bytes: 64 KB + rest
        files = [{'name': f'f{i}.bin', 'url': f'{FILE_URL}{i}',
                  'provider': 'litterbox', 'size': len(body)}
                 for i, body in enumerate(ciphertext)]
        self.insert_encrypted_folder('63015', files)
        expected = b'AXFC1' + (2).to_bytes(4, 'little')
        for frame in ciphertext:
            expected += len(frame).to_bytes(4, 'little') + frame
        with patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(body) for body in ciphertext]
            response = self.client.get('/download-folder-cipher/63015')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, expected)
        self.assertEqual(int(response.headers['Content-Length']), len(expected))
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Content-Type'], 'application/octet-stream')
        # Direct view call: WSGI receives a generator over the fetched chunks,
        # not a prebuilt buffer (the old implementation passed bytes here).
        with patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(body) for body in ciphertext]
            with app.test_request_context('/download-folder-cipher/63015'):
                view_response = download_folder_cipher('63015')
        self.assertTrue(view_response.is_streamed)
        self.assertNotIsInstance(view_response.response, (bytes, bytearray))
        self.assertEqual(b''.join(view_response.response), expected)

    def test_cipher_bundle_rejects_a_second_concurrent_build(self):
        """The route builds at most one retained bundle at a time (Render Free
        is 512 MB). A second overlapping request gets 429 before touching
        storage; closing the first response releases the slot."""
        ciphertext = [b'ENCRYPTED-ONE-0123456789']
        files = [{'name': 'a.bin', 'url': FILE_URL, 'provider': 'litterbox',
                  'size': len(ciphertext[0])}]
        self.insert_encrypted_folder('63040', files)
        with patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(ciphertext[0])]
            first = self.client.get('/download-folder-cipher/63040')
            self.assertEqual(first.status_code, 200)
            # The first body is not yet consumed, so its build slot is held.
            second = self.client.get('/download-folder-cipher/63040')
            self.assertEqual(second.status_code, 429)
            self.assertIn('Too many concurrent archive downloads',
                          second.get_data(as_text=True))
            mock_get.assert_called_once()
            first.close()
            mock_get.side_effect = [self.file_response(ciphertext[0])]
            third = self.client.get('/download-folder-cipher/63040')
            self.assertEqual(third.status_code, 200)
            third.close()
            self.assertEqual(mock_get.call_count, 2)

    def test_corrupt_encrypted_folder_content_returns_500_without_leaks(self):
        self.insert_encrypted_folder('63020', [], content='{not-json')
        page = self.client.get('/share/63020')
        self.assertEqual(page.status_code, 500, page.get_data(as_text=True))
        html = page.get_data(as_text=True)
        self.assertIn('Folder data is corrupt.', html)
        self.assertNotIn('Traceback', html)
        self.assertNotIn('sqlite3', html)

    def test_encrypted_folder_page_client_contract(self):
        source = (Path(__file__).with_name('templates') / 'download.html').read_text(
            encoding='utf-8')
        section = source[source.index('async function deriveShareKey'):
                          source.index('// Feature 11: Markdown/text preview')]
        # Pure DOM-text rendering only: names and decrypted bytes never hit HTML.
        self.assertNotIn('innerHTML', section)
        self.assertIn('nameEl.textContent = entry.name;', section)
        # The folder branch unlocks the authenticated manifest before revealing
        # a single name, then fetches ciphertext through the shared endpoints.
        self.assertIn('unlockFolder(key, data.dataset.manifest, iv,', section)
        self.assertIn('Number(data.dataset.count)', section)
        self.assertIn('data.dataset.folderBase', section)
        self.assertIn('data.dataset.folderBundle', section)
        self.assertIn('downloadFolderEntry(key, keyBase, index, entry)', section)
        self.assertIn('downloadFolderZip(key, bundleUrl, entries)', section)
        self.assertIn('buildStoredZip(parts)', section)
        # Template ships exactly the four folder attributes - no names, URLs or
        # per-file IVs in the pre-unlock page.
        self.assertIn('data-manifest="{{ share.manifest.data }}"', source)
        self.assertIn('data-count="{{ share.count }}"', source)
        self.assertIn("url_for('download_folder_file', key=share.key, index=0)", source)
        self.assertIn("url_for('download_folder_cipher', key=share.key)", source)
        self.assertNotIn('data-files', source)
        self.assertNotIn('share.files }}', section)

    def test_password_batch_client_contract_encrypts_before_upload(self):
        js = self._upload_js()
        self.assertIn('async function encryptFolderBatch(password, files)', js)
        self.assertIn('encrypted = await encryptFolderBatch(password, queue);', js)
        # Batch, text and single-file (separate-code) uploads all send the flag.
        self.assertEqual(js.count('data.append("isEncrypted", "1");'), 3)
        self.assertIn('data.append("salt", encrypted.salt);', js)
        self.assertIn('data.append("iv", encrypted.manifestIv);', js)
        self.assertIn('data.append("manifest", encrypted.manifest);', js)
        # An encryption failure returns before the multipart request is built:
        # no partially encrypted batch can ever reach the wire.
        enc = js.index('await encryptFolderBatch(password, queue);')
        xhr = js.index('uploadRequest(data, batchLabel, "/upload-folder")', enc)
        failure_block = js[enc:xhr]
        self.assertIn('Encryption failed before upload:', failure_block)
        self.assertIn('return;', failure_block)
        # Browser-memory guards for large password batches (hard cap + warning).
        guard_block = js[js.index('const totalBytes = queue.reduce'):xhr]
        self.assertIn('totalBytes > ENCRYPTED_BATCH_MAX_BYTES', guard_block)
        self.assertIn('totalBytes > ENCRYPTED_BATCH_WARN_BYTES', guard_block)
        self.assertIn('const ENCRYPTED_BATCH_MAX_BYTES = 500000000;', js)
        self.assertIn('const ENCRYPTED_BATCH_WARN_BYTES = 200000000;', js)
        # The password field was never silently disabled - only explained.
        self.assertNotIn('passwordBlockedReason', js)
        self.assertIn('encrypted in your browser before upload', js)
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('upload.js?v=9', html)
        self.assertIn('<p class="notice" id="passwordNotice"', html)

    @unittest.skipUnless(shutil.which('node'), 'node is required to run the EFM1 client scripts')
    def test_efm1_cross_language_encrypt_upload_unlock_round_trip(self):
        """The real browser scripts on both sides: node encrypts (upload.js
        functions), Python serves (page + bundle endpoints), node unlocks
        (download.html functions) and verifies tamper rejection."""
        template = Path(__file__).with_name('templates') / 'download.html'
        upload_js = Path(app.root_path) / 'static' / 'upload.js'
        encrypt_script = (
            "const fs = require('fs');\n"
            "const src = fs.readFileSync(process.argv[1], 'utf8');\n"
            "const start = src.indexOf('const hasCrypto');\n"
            "const end = src.indexOf('document.addEventListener(\"paste\"');\n"
            "if (start < 0 || end <= start) process.exit(2);\n"
            "eval(src.slice(start, end));\n"
            "(async () => {\n"
            "  const password = 'correct horse battery staple';\n"
            "  const specs = [\n"
            "    { name: 'hello world.txt', text: 'Hello, EFM1!' },\n"
            "    { name: 'nested/dir/ünïcode-façé.bin', text: 'second payload \\u2728' },\n"
            "  ];\n"
            "  const files = specs.map(s => ({\n"
            "    name: s.name,\n"
            "    size: new TextEncoder().encode(s.text).length,\n"
            "    arrayBuffer: async () => {\n"
            "      const b = new TextEncoder().encode(s.text);\n"
            "      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);\n"
            "    },\n"
            "  }));\n"
            "  const out = await encryptFolderBatch(password, files);\n"
            "  const blobs = [];\n"
            "  for (const blob of out.blobs) {\n"
            "    blobs.push(Buffer.from(await blob.arrayBuffer()).toString('base64'));\n"
            "  }\n"
            "  fs.writeFileSync(process.argv[2], JSON.stringify({\n"
            "    password, salt: out.salt, iv: out.manifestIv, manifest: out.manifest,\n"
            "    blobs, names: specs.map(s => s.name), texts: specs.map(s => s.text),\n"
            "  }));\n"
            "})().catch(e => { console.error(e && e.stack || e); process.exit(1); });\n"
        )
        verify_script = (
            "const fs = require('fs');\n"
            "const html = fs.readFileSync(process.argv[1], 'utf8');\n"
            "const start = html.indexOf('async function deriveShareKey');\n"
            "const end = html.indexOf(\"document.getElementById('unlockBtn')\");\n"
            "if (start < 0 || end <= start) process.exit(2);\n"
            "eval(html.slice(start, end));\n"
            "const toBuf = b64 => Uint8Array.from(Buffer.from(b64, 'base64')).buffer;\n"
            "const rejected = fn => fn().then(() => false, () => true);\n"
            "(async () => {\n"
            "  const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
            "  const out = { names: [], texts: [] };\n"
            "  const key = await deriveShareKey(input.password, input.salt);\n"
            "  const entries = await unlockFolder(key, input.manifest, input.iv, input.count);\n"
            "  out.names = entries.map(e => e.name);\n"
            "  const frames = parseCipherBundle(toBuf(input.bundle), input.count);\n"
            "  for (let i = 0; i < entries.length; i++) {\n"
            "    out.texts.push(new TextDecoder().decode(\n"
            "      await decryptFolderFrame(key, entries[i], frames[i])));\n"
            "  }\n"
            "  out.text0 = new TextDecoder().decode(await decryptFolderFrame(\n"
            "    key, entries[0], Uint8Array.from(Buffer.from(input.frame0, 'base64'))));\n"
            "  const badKey = await deriveShareKey('wrong password', input.salt);\n"
            "  out.wrongPasswordRejected = await rejected(\n"
            "    () => unlockFolder(badKey, input.manifest, input.iv, input.count));\n"
            "  const manifestBytes = Buffer.from(input.manifest, 'base64');\n"
            "  manifestBytes[Math.floor(manifestBytes.length / 2)] ^= 0xFF;\n"
            "  out.tamperedManifestRejected = await rejected(\n"
            "    () => unlockFolder(key, manifestBytes.toString('base64'), input.iv, input.count));\n"
            "  out.countMismatchRejected = await rejected(\n"
            "    () => unlockFolder(key, input.manifest, input.iv, input.count + 1));\n"
            "  const bundleBytes = Buffer.from(input.bundle, 'base64');\n"
            "  const flipped = Buffer.from(bundleBytes);\n"
            "  flipped[9 + 4 + 5] ^= 0xFF;\n"
            "  let tamperedFrame = false;\n"
            "  try {\n"
            "    const tampered = parseCipherBundle(Uint8Array.from(flipped).buffer, input.count);\n"
            "    await decryptFolderFrame(key, entries[0], tampered[0]);\n"
            "  } catch { tamperedFrame = true; }\n"
            "  out.tamperedFrameRejected = tamperedFrame;\n"
            "  const badMagic = Buffer.from(bundleBytes);\n"
            "  badMagic[0] = 0x00;\n"
            "  out.badMagicRejected = await rejected(\n"
            "    async () => parseCipherBundle(Uint8Array.from(badMagic).buffer, input.count));\n"
            "  out.truncatedRejected = await rejected(async () => parseCipherBundle(\n"
            "    Uint8Array.from(bundleBytes.subarray(0, bundleBytes.length - 5)).buffer, input.count));\n"
            "  const trailing = new Uint8Array(bundleBytes.length + 3);\n"
            "  trailing.set(Uint8Array.from(bundleBytes));\n"
            "  out.trailingDataRejected = await rejected(\n"
            "    async () => parseCipherBundle(trailing.buffer, input.count));\n"
            "  out.bundleCountMismatchRejected = await rejected(\n"
            "    async () => parseCipherBundle(toBuf(input.bundle), input.count + 1));\n"
            "  process.stdout.write(JSON.stringify(out));\n"
            "})().catch(e => { console.error(e && e.stack || e); process.exit(1); });\n"
        )
        with tempfile.TemporaryDirectory(prefix='alienx-efm1-') as directory:
            secret_path = Path(directory) / 'secret.json'
            result = subprocess.run(
                ['node', '-e', encrypt_script, str(upload_js), str(secret_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            secret = json.loads(secret_path.read_text(encoding='utf-8'))
            payload = [(BytesIO(base64.b64decode(blob)), name)
                       for blob, name in zip(secret['blobs'], secret['names'])]
            with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                    patch('flask_app.requests.put') as put:
                put.return_value.__enter__.return_value.status_code = 200
                put.return_value.__enter__.return_value.json.side_effect = [
                    {'url': 'https://teststore.private.blob.vercel-storage.com/shares/'
                            f'{index:032x}/blob{index}'}
                    for index in range(len(payload))]
                response = self.client.post('/upload-folder', data={
                    'expire': '1h', 'isEncrypted': '1', 'salt': secret['salt'],
                    'iv': secret['iv'], 'manifest': secret['manifest'], 'file': payload,
                })
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            share, = response.get_json()['uploads']
            self.assertEqual(len(share['files']), 2)
            # Stored/sender names are sanitized; originals live only inside the
            # encrypted manifest the recipient unlocks.
            for entry in share['files']:
                self.assertNotIn('/', entry['name'])
            html = self.client.get(f'/share/{share["key"]}').get_data(as_text=True)
            for name in secret['names']:
                self.assertNotIn(name, html)
            self.assertNotIn('teststore.private.blob.vercel-storage.com', html)

            def data_attr(name):
                match = re.search(rf'data-{name}="([^"]*)"', html)
                self.assertIsNotNone(match, f'missing data-{name}')
                return match.group(1)

            page_salt, page_iv = data_attr('salt'), data_attr('iv')
            manifest_attr = data_attr('manifest')
            count = int(data_attr('count'))
            bundle_path = data_attr('folder-bundle')
            base_path = data_attr('folder-base')
            self.assertEqual(page_salt, secret['salt'])
            self.assertEqual(page_iv, secret['iv'])
            self.assertEqual(manifest_attr, secret['manifest'])
            self.assertEqual(count, len(secret['blobs']))
            self.assertEqual(bundle_path, f'/download-folder-cipher/{share["key"]}')
            self.assertEqual(base_path, f'/download-folder/{share["key"]}/0')
            with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                    patch('flask_app.requests.get') as mock_get:
                mock_get.side_effect = [self.file_response(base64.b64decode(blob))
                                        for blob in secret['blobs']]
                bundle = self.client.get(bundle_path)
            self.assertEqual(bundle.status_code, 200)
            with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                    patch('flask_app.requests.get') as mock_get:
                mock_get.return_value = self.file_response(
                    base64.b64decode(secret['blobs'][0]))
                frame0 = self.client.get(base_path)
            self.assertEqual(frame0.status_code, 200)
            unlock_input = {
                'password': secret['password'], 'salt': page_salt, 'iv': page_iv,
                'manifest': manifest_attr, 'count': count,
                'bundle': base64.b64encode(bundle.data).decode(),
                'frame0': base64.b64encode(frame0.data).decode(),
                'names': secret['names'], 'texts': secret['texts'],
            }
            unlock_path = Path(directory) / 'unlock.json'
            unlock_path.write_text(json.dumps(unlock_input), encoding='utf-8')
            result = subprocess.run(
                ['node', '-e', verify_script, str(template), str(unlock_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            out = json.loads(result.stdout)
        # Recipient sees the original (unsanitized) names and every plaintext.
        self.assertEqual(out['names'], secret['names'])
        self.assertEqual(out['texts'], secret['texts'])
        self.assertEqual(out['text0'], secret['texts'][0])
        # Wrong password and every kind of tampering are rejected before any
        # plaintext is produced.
        self.assertTrue(out['wrongPasswordRejected'])
        self.assertTrue(out['tamperedManifestRejected'])
        self.assertTrue(out['countMismatchRejected'])
        self.assertTrue(out['tamperedFrameRejected'])
        self.assertTrue(out['badMagicRejected'])
        self.assertTrue(out['truncatedRejected'])
        self.assertTrue(out['trailingDataRejected'])
        self.assertTrue(out['bundleCountMismatchRejected'])

    @unittest.skipUnless(shutil.which('node'), 'node is required to run the EFM1 ZIP builder')
    def test_browser_zip_builder_matches_python_zipfile(self):
        template = Path(__file__).with_name('templates') / 'download.html'
        script = (
            "const fs = require('fs');\n"
            "const html = fs.readFileSync(process.argv[1], 'utf8');\n"
            "const start = html.indexOf('function truncateUtf8Name');\n"
            "const end = html.indexOf(\"document.getElementById('unlockBtn')\");\n"
            "if (start < 0 || end <= start) process.exit(2);\n"
            "eval(html.slice(start, end));\n"
            "(async () => {\n"
            "  const enc = new TextEncoder();\n"
            "  const parts = [\n"
            "    { name: 'plain.txt', text: 'hello zip' },\n"
            "    { name: '../evil.txt', text: 'evil body' },\n"
            "    { name: 'deep\\\\..\\\\..\\\\win.bat', text: 'bat body' },\n"
            "    { name: 'plain.txt', text: 'duplicate body' },\n"
            "    { name: 'ünïcode-façé.txt', text: 'unicode body \\u2728' },\n"
            "    { name: '.hidden', text: 'hidden body' },\n"
            "    { name: '.\\\\control\\u0000name.txt', text: 'ctrl body' },\n"
            "  ];\n"
            "  const zip = await buildStoredZip(parts.map(p => (\n"
            "    { name: p.name, data: enc.encode(p.text) })));\n"
            "  fs.writeFileSync(process.argv[2], Buffer.from(zip));\n"
            "  let err = null;\n"
            "  try { await buildStoredZip([{ name: 'big.bin', data: { length: 500000001 } }]); }\n"
            "  catch (e) { err = String(e && e.message || e); }\n"
            "  process.stdout.write(JSON.stringify({ err }));\n"
            "})().catch(e => { console.error(e && e.stack || e); process.exit(1); });\n"
        )
        with tempfile.TemporaryDirectory(prefix='alienx-zip-') as directory:
            zip_path = Path(directory) / 'built.zip'
            result = subprocess.run(
                ['node', '-e', script, str(template), str(zip_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            stats = json.loads(result.stdout)
            expected_names = ['plain.txt', 'evil.txt', 'win.bat', 'plain-2.txt',
                              'ünïcode-façé.txt', 'hidden', 'controlname.txt']
            bodies = [b'hello zip', b'evil body', b'bat body', b'duplicate body',
                      'unicode body ✨'.encode(), b'hidden body', b'ctrl body']
            with zipfile.ZipFile(zip_path) as archive:
                # Python's zipfile verifies structure and every CRC32.
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.namelist(), expected_names)
                for name, body in zip(expected_names, bodies):
                    with self.subTest(entry=name):
                        self.assertEqual(archive.read(name), body)
                self.assertTrue(archive.getinfo('ünïcode-façé.txt').flag_bits & 0x800)
                for name in archive.namelist():
                    with self.subTest(safety=name):
                        self.assertNotIn('/', name)
                        self.assertNotIn('\\', name)
                        self.assertNotIn('..', name)
                        self.assertFalse(name.startswith('.'))
        self.assertEqual(stats['err'],
                         'This share is too large to build as one archive here.')

    def test_expired_batch_cannot_be_downloaded(self):
        files = [{'name': 'a.txt', 'url': FILE_URL, 'provider': 'litterbox', 'size': 1},
                 {'name': 'b.txt', 'url': FILE_URL, 'provider': 'litterbox', 'size': 1}]
        for index, template in enumerate(('/download-folder/{key}/0',
                                          '/download-folder-zip/{key}',
                                          '/share/{key}')):
            key = f'711{index:02d}'
            self.insert_folder(key, '2 files', files, expires=self.now - 1)
            with self.subTest(path=template):
                with patch('flask_app.requests.get') as mock_get:
                    response = self.client.get(template.format(key=key))
                self.assertEqual(response.status_code, 410,
                                 response.get_data(as_text=True))
                self.assertNotIn('a.txt', response.get_data(as_text=True))
                mock_get.assert_not_called()
        with app.app_context():
            self.assertEqual(
                get_db().execute('SELECT COUNT(*) FROM shares WHERE expires <= ?',
                                 (self.now,)).fetchone()[0], 0)

    def test_expired_encrypted_folder_cannot_serve_ciphertext(self):
        """Expiry is enforced before any ciphertext route parses the envelope or
        touches storage, so an expired encrypted folder never hands out bundle
        frames, individual files or a ZIP. One row per route: cleanup deletes
        every expired share on the first request."""
        ciphertext = b'ENCRYPTED-ONE-0123456789'
        files = [{'name': 'alpha secret.txt', 'url': FILE_URL,
                  'provider': 'litterbox', 'size': len(ciphertext)},
                 {'name': 'beta secret.bin', 'url': FILE_URL + 'x',
                  'provider': 'litterbox', 'size': len(ciphertext)}]
        for index, template in enumerate(('/download-folder-cipher/{key}',
                                          '/download-folder/{key}/0',
                                          '/download-folder-zip/{key}')):
            key = f'7119{index}'
            meta = self.insert_encrypted_folder(key, files, expires=self.now - 1)
            with self.subTest(path=template):
                with patch('flask_app.requests.get') as mock_get:
                    response = self.client.get(template.format(key=key))
                self.assertEqual(response.status_code, 410,
                                 response.get_data(as_text=True))
                body = response.get_data(as_text=True)
                self.assertIn('This share has expired.', body)
                self.assertNotIn('alpha secret.txt', body)
                self.assertNotIn('beta secret.bin', body)
                self.assertNotIn(meta['manifest'], body)
                self.assertNotIn('AXFC1', body)
                mock_get.assert_not_called()
        with app.app_context():
            self.assertEqual(
                get_db().execute('SELECT COUNT(*) FROM shares WHERE expires <= ?',
                                 (self.now,)).fetchone()[0], 0)

    def test_batch_upload_accepts_the_full_fifty_file_form_ceiling(self):
        files = [(f'file{i}.txt', f'body-{i}'.encode()) for i in range(50)]
        response = self.batch_upload(files)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        share, = response.get_json()['uploads']
        self.assertEqual(share['name'], '50 files')
        self.assertEqual(len(share['files']), 50)
        too_many = self.batch_upload(files + [('one-too-many.txt', b'x')])
        self.assertEqual(too_many.status_code, 400)
        self.assertIn('1 and 50 files', too_many.get_json()['error'])

    def test_upload_page_multi_file_one_code_contract(self):
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('upload.js?v=9', html)
        self.assertIn('id="multiFileNote"', html)
        self.assertIn('id="passwordNotice"', html)
        js = (Path(app.root_path) / 'static' / 'upload.js').read_text(encoding='utf-8')
        self.assertIn('(mode === "folder" || (queue.length > 1 && !separateCodes))', js)
        # Password batches encrypt before any network call; there is no blocker
        # that silently disables the password field any more.
        self.assertIn('async function encryptFolderBatch(password, files)', js)
        self.assertIn('encrypted = await encryptFolderBatch(password, queue);', js)
        self.assertIn('Encryption failed before upload:', js)
        self.assertIn('ENCRYPTED_BATCH_MAX_BYTES', js)
        self.assertNotIn('passwordBlockedReason', js)
        self.assertIn('MAX_BATCH_FILES = 50', js)
        self.assertIn('"/upload-folder"', js)
        self.assertIn('uploadRequest(data, batchLabel, "/upload-folder")', js)
        self.assertIn('/download-folder-zip/', js)
        self.assertIn('Download All as ZIP', js)
        # Single-file and text uploads still use the original /upload route.
        self.assertIn('xhr = await uploadRequest(data, label);', js)

    def _upload_js(self):
        return (Path(app.root_path) / 'static' / 'upload.js').read_text(encoding='utf-8')

    def test_default_batch_option_off_three_files_share_one_code_and_zip(self):
        html = self.client.get('/').get_data(as_text=True)
        # Default OFF: the option is opt-in and is never pre-checked.
        self.assertIn('id="separateCodes"', html)
        self.assertNotRegex(html, r'<input type="checkbox" id="separateCodes"[^>]*checked')
        self.assertIn('Upload each file with a separate code', html)
        js = self._upload_js()
        # With the option OFF a multi-file selection goes to /upload-folder.
        self.assertIn('(mode === "folder" || (queue.length > 1 && !separateCodes))', js)
        self.assertIn('"/upload-folder"', js)
        files = [('one.txt', b'ONE-BODY'), ('two.txt', b'TWO-BODY'), ('three.txt', b'THREE-BODY')]
        response = self.batch_upload(files, expire='12h')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(result['success'])
        self.assertEqual(result['errors'], [])
        share, = result['uploads']
        # Exactly ONE share code and ONE expiry for the three files.
        with app.app_context():
            rows = get_db().execute('SELECT key, type, expires FROM shares').fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['key'], share['key'])
        self.assertEqual(share['type'], 'folder')
        self.assertEqual(share['name'], '3 files')
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 43200)
        self.assertEqual([f['name'] for f in share['files']],
                         ['one.txt', 'two.txt', 'three.txt'])
        # The share page lists every file with its own Download action...
        page_html = self.client.get(f'/share/{share["key"]}').get_data(as_text=True)
        self.assertIn('Download All as ZIP', page_html)
        for index, (name, _) in enumerate(files):
            with self.subTest(index=index):
                self.assertIn(f'/download-folder/{share["key"]}/{index}', page_html)
                self.assertIn(name, page_html)
        # ...each file streams individually...
        for index, (_, body) in enumerate(files):
            with self.subTest(index=index):
                with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                        patch('flask_app.requests.get') as mock_get:
                    mock_get.return_value = self.file_response(body)
                    single = self.client.get(f'/download-folder/{share["key"]}/{index}')
                self.assertEqual(single.status_code, 200, single.get_data(as_text=True))
                self.assertEqual(single.data, body)
        # ...and the batch ZIP holds all three.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.get') as mock_get:
            mock_get.side_effect = [self.file_response(body) for _, body in files]
            archive = self.client.get(f'/download-folder-zip/{share["key"]}')
        self.assertEqual(archive.status_code, 200)
        with zipfile.ZipFile(BytesIO(archive.data)) as bundle:
            self.assertEqual(bundle.namelist(), ['one.txt', 'two.txt', 'three.txt'])
            self.assertEqual(bundle.read('two.txt'), b'TWO-BODY')

    def test_separate_codes_option_creates_three_independent_file_shares(self):
        js = self._upload_js()
        self.assertIn('function separateCodesEnabled(mode)', js)
        self.assertIn('mode === "file" && Boolean(separateCodesInput && '
                      'separateCodesInput.checked)', js)
        self.assertIn('queue.length > 1 && !separateCodes', js)
        # The setting is only read; nothing ever switches it on or off for the user.
        self.assertNotRegex(js, r'separateCodesInput\.checked\s*=')
        # Option ON posts each file through the untouched single-file /upload flow.
        self.mock_provider()
        keys = []
        for index, name in enumerate(('one.txt', 'two.txt', 'three.txt')):
            with self.subTest(name=name):
                response = self.client.post('/upload', data={
                    'mode': 'file', 'storageProvider': 'litterbox', 'expire': '72h',
                    'file': (BytesIO(f'body-{index}'.encode()), name),
                })
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                result = response.get_json()
                self.assertTrue(result['success'])
                self.assertEqual(result['errors'], [])
                share, = result['uploads']
                self.assertEqual(share['type'], 'file')
                self.assertEqual(share['name'], name)
                # The selected expiry is preserved for every file.
                self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(),
                                 self.now + 259200)
                keys.append(share['key'])
        self.assertEqual(len(set(keys)), 3)
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 3)
        for key in keys:
            with self.subTest(key=key):
                self.assertEqual(self.client.get(f'/share/{key}').status_code, 200)
        self.assertEqual(self.post.call_count, 3)

    def test_exactly_one_file_keeps_the_original_single_file_path(self):
        js = self._upload_js()
        # A single selected file never takes the batch branch, whatever the option says.
        self.assertIn('queue.length > 1 && !separateCodes', js)
        self.assertIn('xhr = await uploadRequest(data, label);', js)
        self.mock_provider()
        response = self.client.post('/upload', data={
            'mode': 'file', 'storageProvider': 'litterbox', 'expire': '1h',
            'file': (BytesIO(b'only-one'), 'solo.txt'),
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        share, = response.get_json()['uploads']
        self.assertEqual(share['type'], 'file')
        self.assertEqual(share['name'], 'solo.txt')
        with app.app_context():
            rows = get_db().execute('SELECT key, type FROM shares').fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['type'], 'file')
        # No batch listing and no ZIP button on a one-file share.
        page_html = self.client.get(f'/share/{share["key"]}').get_data(as_text=True)
        self.assertIn('id="previewContainer"', page_html)
        self.assertNotIn('Download All as ZIP', page_html)

    def test_folder_uploads_ignore_the_separate_codes_option(self):
        js = self._upload_js()
        # Folder mode is tested before the option is consulted, so it cannot apply.
        self.assertIn('(mode === "folder" || (queue.length > 1 && !separateCodes))', js)
        # ...and the control is disabled outside the File tab instead of silently ignored.
        self.assertIn('separateCodesInput.disabled = mode !== "file"', js)
        self.assertIn('function separateCodesEnabled(mode) {\n    return mode === "file"', js)
        # Folder behaviour itself is unchanged: one share, flattened paths, one code.
        files = [('docs/readme.md', b'# readme'), ('docs/app.py', b'print(1)')]
        response = self.batch_upload(files, expire='72h')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        share, = response.get_json()['uploads']
        self.assertEqual(share['type'], 'folder')
        self.assertEqual(share['name'], '2 files')
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 259200)
        self.assertEqual([f['name'] for f in share['files']],
                         ['docs_readme.md', 'docs_app.py'])
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 1)

    def test_separate_code_failures_are_reported_without_hiding_successes(self):
        self.mock_provider()
        outcomes = []
        for name, body in (('good1.txt', b'G1'), ('bad.exe', b'nope'), ('good2.txt', b'G2')):
            outcomes.append(self.client.post('/upload', data={
                'mode': 'file', 'storageProvider': 'litterbox', 'expire': '1h',
                'file': (BytesIO(body), name),
            }))
        good1, bad, good2 = outcomes
        # The valid files still upload and keep their own codes...
        for good, name in ((good1, 'good1.txt'), (good2, 'good2.txt')):
            with self.subTest(name=name):
                self.assertEqual(good.status_code, 200, good.get_data(as_text=True))
                result = good.get_json()
                self.assertTrue(result['success'])
                self.assertEqual(result['errors'], [])
                self.assertEqual(result['uploads'][0]['name'], name)
                self.assertEqual(result['uploads'][0]['type'], 'file')
        # ...while the rejected file is named in the error and stores nothing.
        self.assertEqual(bad.status_code, 400)
        body_json = bad.get_json()
        self.assertFalse(body_json['success'])
        self.assertEqual(body_json['uploads'], [])
        self.assertEqual(len(body_json['errors']), 1)
        self.assertIn('bad.exe', body_json['errors'][0])
        self.assertIn('blocked', body_json['errors'][0])
        keys = [good1.get_json()['uploads'][0]['key'], good2.get_json()['uploads'][0]['key']]
        self.assertNotEqual(keys[0], keys[1])
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 2)
        # Only the two valid files ever reached storage.
        self.assertEqual(self.post.call_count, 2)

    def test_separate_codes_option_does_not_regress_encryption_preview_or_limits(self):
        # Upload limits are unchanged: /upload still caps 10 files per request...
        response = self.client.post('/upload', data={'storageProvider': 'litterbox',
                                                     'expire': '1h',
                                                     'file': [(BytesIO(b'x'), f'{i}.txt')
                                                              for i in range(11)]})
        self.assertEqual(response.status_code, 400)
        self.assertIn('between 1 and 10 files', response.get_json()['error'])
        # ...and a batch still caps at 50 files.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            response = self.client.post('/upload-folder', data={
                'expire': '1h',
                'file': [(BytesIO(b'x'), f'{i}.txt') for i in range(51)],
            })
        self.assertEqual(response.status_code, 400)
        self.assertIn('between 1 and 50 files', response.get_json()['error'])
        self.post.assert_not_called()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)
        # Single-file password encryption is unaffected by the new option.
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            response = self.client.post('/upload', data={
                'mode': 'file', 'storageProvider': 'vercel', 'expire': '1h',
                'isEncrypted': '1', 'salt': 'c2FsdA==', 'iv': 'aXY=',
                'file': (BytesIO(b'ciphertext-bytes'), 'secret.txt'),
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        share, = response.get_json()['uploads']
        self.assertTrue(share['is_encrypted'])
        share_html = self.client.get(f'/share/{share["key"]}').get_data(as_text=True)
        self.assertIn('password-prompt', share_html)
        self.assertNotIn('id="previewContainer"', share_html)
        # Ciphertext is still never proxied by the preview endpoint.
        with patch('flask_app.requests.get') as mock_get:
            preview = self.client.get(f'/api/preview/{share["key"]}')
            mock_get.assert_not_called()
        self.assertEqual(preview.status_code, 400)

    def test_upload_page_separate_codes_option_contract(self):
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('upload.js?v=9', html)
        self.assertIn('id="separateCodes"', html)
        self.assertIn('for="separateCodes"', html)
        self.assertNotRegex(html, r'<input type="checkbox" id="separateCodes"[^>]*checked')
        self.assertIn('Upload each file with a separate code', html)
        self.assertIn('id="separateCodesHint"', html)
        self.assertIn('Generate a separate share code and link for every file instead of '
                      'sharing all files under one code.', html)
        # The control lives inside the existing Advanced options section.
        summary = html.index('Advanced options')
        box = html.index('id="separateCodes"')
        self.assertTrue(summary < box < html.index('</details>', summary))
        js = self._upload_js()
        self.assertIn('const separateCodesInput = document.getElementById("separateCodes");', js)
        self.assertIn('separateCodesInput.disabled = mode !== "file"', js)
        self.assertIn('separateCodesInput.addEventListener("change", updateFiles)', js)
        self.assertIn('(queue.length > 1 && !separateCodes)', js)
        self.assertIn('files will each get their own share code, link and expiry', js)
        # Never auto-switched by file count, and the single-file route is untouched.
        self.assertNotRegex(js, r'separateCodesInput\.checked\s*=')
        self.assertIn('xhr = await uploadRequest(data, label);', js)


if __name__ == '__main__':
    unittest.main()
