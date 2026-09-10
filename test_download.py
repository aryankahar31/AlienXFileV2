import os
import json
import re
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import unittest
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

from flask_app import app, get_db


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
                                     UPLOAD_MAX_BYTES=95_000_000, LITTERBOX_MAX_BYTES=1_000_000_000,
                                     MAX_CONTENT_LENGTH=1_001_000_000,
                                     UPLOAD_RATE_LIMIT=1000, LOOKUP_RATE_LIMIT=1000,
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
        for name, value in {'type': 'text', 'inputmode': 'numeric', 'pattern': '[0-9]{5}',
                            'minlength': '5', 'maxlength': '5', 'autocomplete': 'off'}.items():
            self.assertEqual(field[name], value)
        self.assertIn('required', field)
        for key in ('', '1234', '123456', 'abcde', '+1234', '12.34', '12 34',
                    '\uff11\uff12\uff13\uff14\uff15', '\u0661\u0662\u0663\u0664\u0665',
                    "' OR 1=1", 'https://evil.example'):
            with self.subTest(key=key):
                response = self.client.post('/download', data={'key': key})
                self.assertEqual(response.status_code, 400)
                self.assertIn(b'5-digit code', response.data)
                self.assertEqual(self.assert_download_form(response)['value'], key)
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
            self.assertTrue(all(attrs.get('src') == '/qr/00007' for tag, attrs in tags if tag == 'img'))
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
                ('vercel', 0, 200), ('vercel', 8, 200), ('vercel', 9, 400),
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
                        if provider == 'vercel':
                            self.assertIn('Litterbox', response.get_json()['errors'][0])
            self.assertEqual(put.call_count, 2)
            self.assertEqual(self.post.call_count, 3)
            for provider, size in (('vercel', 8), ('litterbox', 32)):
                response = self.client.post('/upload', data={'storageProvider': provider, 'file': [
                    (BytesIO(b'x' * size), 'one.txt'), (BytesIO(b'y' * size), 'two.txt'),
                ]})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.get_json()['uploads']), 2)
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 9)

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

    def test_vercel_failure_never_retries_with_litterbox(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask_app.requests.put', side_effect=requests.Timeout('private detail')) as put:
            response = self.client.post('/upload', data={
                'storageProvider': 'vercel', 'file': (BytesIO(b'x'), 'test.txt'),
            })
            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.get_json()['success'])
            self.assertEqual(response.get_json()['uploads'], [])
            self.assertEqual(len(response.get_json()['errors']), 1)
            self.assertNotIn(b'private detail', response.data)
            put.assert_called_once()
        self.post.assert_not_called()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)

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

    def test_vercel_limit_message_uses_decimal_95_mb_and_suggests_litterbox(self):
        # Report a large parsed-file size without allocating or sending a large body.
        stream = BytesIO()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN), \
                patch('flask.wrappers.Request._get_file_stream', return_value=stream), \
                patch.object(stream, 'tell', return_value=95_000_001), \
                patch('flask_app.requests.put') as put:
            response = self.client.post('/upload', data={
                'storageProvider': 'vercel', 'file': (BytesIO(b'x'), 'large.txt'),
            })
            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.get_json()['success'])
            self.assertEqual(response.get_json()['uploads'], [])
            error, = response.get_json()['errors']
            self.assertIn('95 MB', error)
            self.assertIn('Litterbox', error)
            put.assert_not_called()
        self.post.assert_not_called()
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM shares').fetchone()[0], 0)

    def test_default_provider_limits_leave_room_for_litterbox_requests(self):
        result = subprocess.run([sys.executable, '-B', '-c', '''
from flask_app import app
assert app.config['UPLOAD_MAX_BYTES'] == 95_000_000
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
                self.assertEqual([row['name'] for row in schema], [*columns, 'provider'])
                self.assertEqual(schema[-1]['type'].upper(), 'TEXT')
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
                column = db.execute('PRAGMA table_info(shares)').fetchall()[-1]
                self.assertEqual((column['name'], column['type'], column['dflt_value']),
                                 ('provider', 'TEXT', "'vercel'"))
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


if __name__ == '__main__':
    unittest.main()
