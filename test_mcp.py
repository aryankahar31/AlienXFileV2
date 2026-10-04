import base64
import json
import os
import socket
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import requests

from flask_app import app, get_db, save_share
import mcp

FILE_URL = 'https://litter.catbox.moe/abc123.txt'
BLOB_TOKEN = 'vercel_blob_rw_teststore_fakecredential'
BLOB_URL = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32 + '/report.pdf'
WEBSITE = 'https://alienxfilev2.onrender.com'
SIGNED_URL = ('https://files.oaiusercontent.com/file-abc123?se=2026-10-04T00%3A00%3A00Z'
              '&sig=fake-signature%2Fmust-never-leak&sp=r&sv=2024-11-04&rs=b7H2')


class FakeResponse:
    """Minimal streaming response double for mcp's file fetch."""

    def __init__(self, status_code=200, headers=None, chunks=()):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self._chunks = [bytes(chunk) for chunk in chunks]
        self.iter_called = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def iter_content(self, chunk_size=None):
        self.iter_called = True
        return iter(self._chunks)


class McpTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='alienx-mcp-test-')
        self.addCleanup(directory.cleanup)
        self.database = str(Path(directory.name) / 'shares.sqlite3')
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(patch.dict(
            app.config, TESTING=True, DATABASE=self.database, DATABASE_URL=None,
            BLOB_READ_WRITE_TOKEN='', INDEXNOW_KEY='',
            UPLOAD_MAX_BYTES=1_000_000_000, LITTERBOX_MAX_BYTES=1_000_000_000,
            MAX_CONTENT_LENGTH=1_001_000_000,
            UPLOAD_RATE_LIMIT=1000, LOOKUP_RATE_LIMIT=1000, RATE_WINDOW_SECONDS=60,
            TRUST_PYTHONANYWHERE_PROXY=False, TRUST_RENDER_PROXY=False,
            MCP_ENABLED=True, MCP_API_KEY='', MCP_MAX_UPLOAD_BYTES=26_214_400,
            MCP_RATE_LIMIT=1000, MCP_LOOKUP_RATE_LIMIT=1000, MCP_RATE_WINDOW=600,
            MCP_PUBLIC_BASE_URL='',
            MCP_ALLOWED_ORIGINS='https://chatgpt.com,https://chat.openai.com'))
        self.now = 1_800_000_000
        self.clock = contexts.enter_context(patch('flask_app.time.time', return_value=self.now))
        contexts.enter_context(patch('flask_app.secrets.randbelow', side_effect=range(100_000)))
        # Fail closed: an accidentally unmocked external request must never upload data.
        contexts.enter_context(patch('requests.sessions.Session.request',
                                side_effect=AssertionError('Unexpected network request')))
        self.post = contexts.enter_context(patch('flask_app.requests.post',
                                           side_effect=AssertionError('Unexpected upload')))
        self.client = app.test_client()

    # ── helpers ──────────────────────────────────────────────────────────────

    def rpc(self, method, params=None, request_id=1, **kwargs):
        body = {'jsonrpc': '2.0', 'id': request_id, 'method': method}
        if params is not None:
            body['params'] = params
        response = self.client.post('/mcp', json=body, **kwargs)
        return response, response.get_json(silent=True)

    def call_tool(self, name, arguments=None, request_id=1, expect_error=None):
        response, payload = self.rpc('tools/call',
                                     {'name': name, 'arguments': arguments if arguments is not None else {}},
                                     request_id)
        self.assertEqual(response.status_code, 200, payload)
        self.assertNotIn('error', payload)
        result = payload['result']
        if expect_error is not None:
            self.assertEqual(result['isError'], expect_error, result)
        text = result['content'][0]['text']
        self.assertIsInstance(text, str)
        return result, text

    def tool_json(self, name, arguments=None, request_id=1):
        _, text = self.call_tool(name, arguments, request_id, expect_error=False)
        return json.loads(text)

    def mock_provider(self, link=FILE_URL, status=200):
        response = requests.Response()
        response.status_code = status
        response.url = 'https://litterbox.catbox.moe/resources/internals/api.php'
        response._content = link.encode('utf-8')
        response._content_consumed = True
        self.post.side_effect = None
        self.post.return_value = response
        return response

    def mock_blob_upload(self):
        put = patch('flask_app.requests.put')
        mocked = put.start()
        self.addCleanup(put.stop)
        mocked.return_value.__enter__.return_value.status_code = 200
        mocked.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
        return mocked

    def mock_file_get(self, return_value=None, side_effect=None):
        get = patch('mcp.requests.get')
        mocked = get.start()
        self.addCleanup(get.stop)
        mocked.return_value = return_value
        mocked.side_effect = side_effect
        return mocked

    def mock_public_dns(self):
        # Offline-friendly stand-in: allowlisted hosts resolve to a public IP.
        patched = patch('flask_app.socket.getaddrinfo',
                        return_value=[(socket.AF_INET, socket.SOCK_STREAM,
                                       socket.IPPROTO_TCP, '', ('23.22.3.10', 443))])
        mocked = patched.start()
        self.addCleanup(patched.stop)
        return mocked

    def create_share(self, **kwargs):
        # share_details() builds absolute page URLs, so it needs a request context.
        with app.test_request_context('/'):
            return save_share(**kwargs)

    # ── protocol handshake ───────────────────────────────────────────────────

    def test_initialize_reports_capabilities_and_instructions(self):
        response, payload = self.rpc('initialize',
                                     {'protocolVersion': '2025-06-18',
                                      'clientInfo': {'name': 'mcp-test-client'}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['jsonrpc'], '2.0')
        self.assertEqual(payload['id'], 1)
        result = payload['result']
        self.assertEqual(result['protocolVersion'], '2025-06-18')
        self.assertEqual(result['capabilities'], {'tools': {}})
        self.assertEqual(result['serverInfo'],
                         {'name': 'AlienXFile', 'title': 'AlienXFile', 'version': '2.0.0'})
        instructions = result['instructions']
        self.assertIn(WEBSITE, instructions)
        self.assertIn('password', instructions.lower())
        self.assertIn('expire', instructions.lower())
        # Modern ChatGPT clients ask for 2025-11-25: it must be echoed back.
        _, payload = self.rpc('initialize', {'protocolVersion': '2025-11-25'}, request_id=5)
        self.assertEqual(payload['result']['protocolVersion'], '2025-11-25')
        # Unsupported protocol versions fall back to the latest supported legacy one.
        _, payload = self.rpc('initialize', {'protocolVersion': '1999-01-01'}, request_id=2)
        self.assertEqual(payload['result']['protocolVersion'], '2025-11-25')
        # Omitting params entirely is still a valid initialize.
        _, payload = self.rpc('initialize', request_id=3)
        self.assertEqual(payload['result']['protocolVersion'], '2025-11-25')
        # Non-object params are a protocol error, not a crash.
        response, payload = self.rpc('initialize', ['not-an-object'], request_id=4)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['error']['code'], -32602)

    def test_ping_notifications_and_unknown_method(self):
        response, payload = self.rpc('ping')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['result'], {})
        notification = self.client.post('/mcp', json={'jsonrpc': '2.0',
                                                      'method': 'notifications/initialized'})
        self.assertEqual(notification.status_code, 202)
        self.assertEqual(notification.data, b'')
        response, payload = self.rpc('resources/list', request_id=9)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['error'], {'code': -32601,
                                            'message': 'Method not found: resources/list.'})
        self.assertEqual(payload['id'], 9)

    def test_server_discover_is_implemented_for_modern_clients(self):
        # ChatGPT's client (openai-mcp) calls server/discover with a string id
        # before/alongside initialize; MCP 2026-07-28 requires servers to
        # implement it, and a -32601 there makes modern clients fail.
        response, payload = self.rpc('server/discover', request_id='openai-mcp-discover')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['id'], 'openai-mcp-discover')
        result = payload['result']
        self.assertEqual(result['resultType'], 'complete')
        self.assertEqual(result['supportedVersions'],
                         ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'])
        self.assertEqual(result['capabilities'], {'tools': {}})
        self.assertEqual(result['_meta']['io.modelcontextprotocol/serverInfo'],
                         {'name': 'AlienXFile', 'version': '2.0.0'})
        self.assertIn('AlienXFile', result['instructions'])
        # Every legacy initialize version must also be advertised here.
        for version in ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'):
            self.assertIn(version, result['supportedVersions'])

    def test_cors_preflight_and_headers_for_allowlisted_origins(self):
        preflight = self.client.options('/mcp',
                                        headers={'Origin': 'https://chatgpt.com',
                                                 'Access-Control-Request-Method': 'POST',
                                                 'Access-Control-Request-Headers':
                                                     'content-type, mcp-protocol-version, '
                                                     'authorization'})
        self.assertEqual(preflight.status_code, 204)
        self.assertEqual(preflight.headers['Access-Control-Allow-Origin'], 'https://chatgpt.com')
        allow_headers = preflight.headers['Access-Control-Allow-Headers'].lower()
        for header in ('content-type', 'authorization', 'mcp-protocol-version', 'mcp-session-id'):
            self.assertIn(header, allow_headers)
        self.assertIn('POST', preflight.headers['Access-Control-Allow-Methods'])
        # Allowed origin on a real POST gains the same CORS headers.
        response = self.client.post('/mcp',
                                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                                    headers={'Origin': 'https://chat.openai.com'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                         'https://chat.openai.com')
        self.assertIn('Origin', response.headers['Vary'])
        # Disallowed origins: preflight and POST are both rejected, no CORS.
        for origin in ('https://evil.example', 'https://openai.com.evil.example'):
            with self.subTest(origin=origin):
                preflight = self.client.options('/mcp', headers={'Origin': origin})
                self.assertEqual(preflight.status_code, 403)
                self.assertNotIn('Access-Control-Allow-Origin', preflight.headers)
                post = self.client.post('/mcp',
                                        json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                                        headers={'Origin': origin})
                self.assertEqual(post.status_code, 403)
                self.assertNotIn('Access-Control-Allow-Origin', post.headers)
        # No Origin (curl, server-side SDKs): plain 204 without CORS echo.
        anonymous = self.client.options('/mcp')
        self.assertEqual(anonymous.status_code, 204)
        self.assertNotIn('Access-Control-Allow-Origin', anonymous.headers)

    def test_mcp_trailing_slash_serves_without_redirect(self):
        for path in ('/mcp', '/mcp/'):
            with self.subTest(path=path):
                response = self.client.post(path, json={'jsonrpc': '2.0', 'id': 1,
                                                        'method': 'ping'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['result'], {})

    def test_tools_list_catalog_and_annotations(self):
        _, payload = self.rpc('tools/list')
        tools = payload['result']['tools']
        self.assertEqual([tool['name'] for tool in tools],
                         ['upload_file', 'share_text', 'get_shared_content',
                          'get_shared_file', 'check_share'])
        by_name = {tool['name']: tool for tool in tools}
        self.assertEqual(by_name['upload_file']['inputSchema']['required'], [])
        self.assertEqual(by_name['share_text']['inputSchema']['required'], ['text'])
        self.assertTrue(by_name['get_shared_content']['annotations']['readOnlyHint'])
        self.assertTrue(by_name['get_shared_file']['annotations']['readOnlyHint'])
        self.assertTrue(by_name['check_share']['annotations']['readOnlyHint'])
        self.assertFalse(by_name['upload_file']['annotations']['readOnlyHint'])
        self.assertFalse(by_name['share_text']['annotations']['readOnlyHint'])
        for tool in tools:
            with self.subTest(tool=tool['name']):
                self.assertEqual(tool['inputSchema']['additionalProperties'], False)
                # Anonymous mode must not advertise a non-standard scheme type.
                self.assertNotIn('securitySchemes', tool)
                self.assertNotIn('security', tool)
                self.assertFalse(tool['annotations']['destructiveHint'])
                self.assertFalse(tool['annotations']['openWorldHint'])
        self.assertEqual(by_name['check_share']['inputSchema']['properties']['code']['pattern'],
                         '^[A-Za-z0-9]{3,20}$')
        # The published security scheme appears only when an API key is configured.
        with patch.dict(app.config, MCP_API_KEY='sekret-key-value'):
            _, payload = self.rpc('tools/list', request_id=2,
                                  headers={'Authorization': 'Bearer sekret-key-value'})
            upload = next(tool for tool in payload['result']['tools']
                          if tool['name'] == 'upload_file')
            self.assertEqual(upload['securitySchemes']['bearerAuth']['type'], 'http')
            self.assertEqual(upload['securitySchemes']['bearerAuth']['scheme'], 'bearer')
            self.assertEqual(upload['security'], [{'bearerAuth': []}])
            self.assertNotIn('none', json.dumps(upload['securitySchemes']))

    def test_upload_file_schema_declares_openai_file_param(self):
        _, payload = self.rpc('tools/list')
        tools = payload['result']['tools']
        self.assertEqual(len(tools), 5)
        upload = next(tool for tool in tools if tool['name'] == 'upload_file')
        self.assertEqual(upload['_meta'], {'openai/fileParams': ['file']})
        schema = upload['inputSchema']
        self.assertEqual(schema['required'], [])
        self.assertIn('file', schema['properties'])
        self.assertEqual(schema['properties']['file']['$ref'], '#/$defs/OpenAIFile')
        definition = schema['$defs']['OpenAIFile']
        self.assertEqual(definition['type'], 'object')
        self.assertEqual(sorted(definition['properties']),
                         ['download_url', 'file_id', 'file_name', 'mime_type'])
        for key in ('download_url', 'file_id', 'mime_type', 'file_name'):
            with self.subTest(key=key):
                self.assertEqual(definition['properties'][key]['type'], 'string')
        self.assertEqual(definition['required'], ['download_url', 'file_id'])
        self.assertFalse(definition['additionalProperties'])
        # No other tool grows a file param declaration.
        for tool in tools:
            with self.subTest(tool=tool['name']):
                if tool['name'] != 'upload_file':
                    self.assertNotIn('_meta', tool)
                    self.assertNotIn('$defs', tool['inputSchema'])

    # ── share_text tool ──────────────────────────────────────────────────────

    def test_share_text_roundtrip_and_public_urls(self):
        with patch.dict(app.config, MCP_PUBLIC_BASE_URL='https://files.example.test'):
            created = self.tool_json('share_text', {
                'text': 'hello from mcp\nsecond line',
                'expires_in': '1 hour',
                'custom_code': 'roundtrip',
            })
            self.assertTrue(created['success'])
            self.assertEqual(created['code'], 'roundtrip')
            self.assertEqual(created['share_url'], 'https://files.example.test/share/roundtrip')
            self.assertEqual(created['download_url'],
                             'https://files.example.test/download/roundtrip')
            self.assertEqual(created['expires_in'], '1h')
            self.assertEqual(datetime.fromisoformat(created['expires_at']).timestamp(),
                             self.now + 3600)
            content = self.tool_json('get_shared_content', {'code': 'roundtrip'})
        self.assertEqual(content['text'], 'hello from mcp\nsecond line')
        self.assertEqual(content['length'], len('hello from mcp\nsecond line'))
        self.assertEqual(content['type'], 'text')
        self.assertFalse(content['is_encrypted'])
        self.assertEqual(content['download_url'],
                         'https://files.example.test/download/roundtrip')
        # Without a configured base URL the website URL is used instead.
        created = self.tool_json('share_text', {'text': 'default base url'})
        self.assertEqual(created['code'], '00000')
        self.assertEqual(created['share_url'], WEBSITE + '/share/00000')
        self.assertEqual(created['download_url'], WEBSITE + '/download/00000')

    def test_expiry_aliases_are_accepted_and_strict(self):
        cases = [('1h', 3600), ('1 hour', 3600), ('12h', 43200), ('24h', 86400),
                 ('1d', 86400), ('1 Day', 86400), ('tomorrow', 86400),
                 ('TOMORROW', 86400), ('72h', 259200), ('3d', 259200),
                 ('3 days', 259200), ('168h', 604800), ('7d', 604800),
                 ('1 week', 604800), (None, 86400), ('', 86400)]
        for index, (value, seconds) in enumerate(cases):
            with self.subTest(expires_in=value):
                arguments = {'text': f'note number {index}'}
                if value is not None:
                    arguments['expires_in'] = value
                created = self.tool_json('share_text', arguments)
                self.assertEqual(datetime.fromisoformat(created['expires_at']).timestamp(),
                                 self.now + seconds)
                self.assertEqual(created['code'], f'{index:05d}')
        for bad in ('9 days', '5m', '0h', 'P1D', 'forever', '25 hours', '-1h', 3600):
            with self.subTest(invalid=bad):
                _, text = self.call_tool('share_text',
                                         {'text': 'x', 'expires_in': bad},
                                         expect_error=True)
                self.assertIn('expires_in', text)

    def test_expiry_spoken_forms_are_normalised(self):
        cases = [('12 hours', 43200, '12h'), ('12 hour', 43200, '12h'),
                 ('12hr', 43200, '12h'), ('1 hours', 3600, '1h'),
                 ('3 day', 259200, '72h'), ('72 hours', 259200, '72h'),
                 ('1 week', 604800, '168h'), ('  12 HOURS ', 43200, '12h')]
        for index, (value, seconds, canonical) in enumerate(cases):
            with self.subTest(expires_in=value):
                created = self.tool_json('share_text',
                                         {'text': f'spoken form {value!r}',
                                          'expires_in': value})
                self.assertEqual(created['expires_in'], canonical)
                self.assertEqual(datetime.fromisoformat(created['expires_at']).timestamp(),
                                 self.now + seconds)
                self.assertEqual(created['code'], f'{index:05d}')
        for bad in ('2 days', '6 hours', '5 minutes'):
            with self.subTest(invalid=bad):
                _, text = self.call_tool('share_text',
                                         {'text': 'x', 'expires_in': bad},
                                         expect_error=True)
                self.assertIn('expires_in', text)
                self.assertIn('Allowed expires_in values', text)

    def test_share_text_validation_errors(self):
        cases = [
            ({}, 'Missing required argument "text"'),
            ({'text': ''}, 'cannot be blank'),
            ({'text': '   \n  '}, 'cannot be blank'),
            ({'text': 'a\x00b'}, 'null characters'),
            ({'text': 'x' * 100_001}, 'maximum 100000'),
            ({'text': 42}, 'must be a string'),
            ({'text': 'ok', 'custom_code': 'bad-code'}, 'Custom code must be 3-20'),
            ({'text': 'ok', 'custom_code': 'ab'}, 'Custom code must be 3-20'),
            ({'text': 'ok', 'custom_code': 'x' * 21}, 'Custom code must be 3-20'),
        ]
        for arguments, needle in cases:
            with self.subTest(needle=needle):
                _, text = self.call_tool('share_text', arguments, expect_error=True)
                self.assertIn(needle, text)
                self.assertNotIn('Traceback', text)

    # ── upload_file tool ─────────────────────────────────────────────────────

    def test_upload_file_roundtrip_with_metadata_and_inline_text(self):
        payload_bytes = b'MCP upload bytes'
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            put = self.mock_blob_upload()
            created = self.tool_json('upload_file', {
                'filename': 'report.txt',
                'content_base64': base64.b64encode(payload_bytes).decode(),
                'expires_in': '7d',
                'custom_code': 'mcpfile',
            })
            self.assertEqual(created['code'], 'mcpfile')
            self.assertEqual(created['filename'], 'report.txt')
            self.assertEqual(created['size'], len(payload_bytes))
            self.assertEqual(datetime.fromisoformat(created['expires_at']).timestamp(),
                             self.now + 604800)
            self.assertEqual(put.call_args.kwargs['headers']['x-vercel-blob-access'], 'private')
            self.assertEqual(put.call_args.kwargs['headers']['Authorization'], 'Bearer ' + BLOB_TOKEN)
            # Metadata plus a website download link, never the storage URL.
            meta = self.tool_json('get_shared_file', {'code': 'mcpfile'})
            self.assertEqual(meta['type'], 'file')
            self.assertEqual(meta['filename'], 'report.txt')
            self.assertEqual(meta['size'], len(payload_bytes))
            self.assertFalse(meta['is_encrypted'])
            self.assertEqual(meta['download_url'], WEBSITE + '/download/mcpfile')
            self.assertNotIn(BLOB_URL, json.dumps(meta))
            # Small text-like files come back inline through the preview proxy.
            upstream = requests.Response()
            upstream.status_code = 200
            upstream._content = payload_bytes
            upstream._content_consumed = True
            upstream.headers['Content-Type'] = 'text/plain'
            with patch('flask_app.requests.get') as get:
                get.return_value = upstream
                content = self.tool_json('get_shared_content', {'code': 'mcpfile'})
        self.assertTrue(content['content_available'])
        self.assertEqual(content['text'], 'MCP upload bytes')
        self.assertFalse(content['is_encrypted'])

    def test_upload_file_rejects_bad_input_before_any_storage(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            put = self.mock_blob_upload()
            cases = [
                ({}, 'Provide one of "file"'),
                ({'filename': 'a.txt'}, 'Provide one of "file"'),
                ({'content_base64': 'AAAA'}, 'Missing required argument "filename"'),
                ({'filename': 7, 'content_base64': 'AAAA'}, 'must be a string'),
                ({'filename': 'a.txt', 'content_base64': 5}, 'must be a string'),
                ({'filename': '', 'content_base64': 'AAAA'}, 'filename must be a non-empty'),
                ({'filename': 'x' * 256, 'content_base64': 'AAAA'}, 'filename is too long'),
                ({'filename': 'bad\x01name.txt', 'content_base64': 'AAAA'}, 'control characters'),
                ({'filename': 'evil.exe', 'content_base64': 'AAAA'}, '".exe" extension are blocked'),
                ({'filename': 'evil.bat', 'content_base64': 'AAAA'}, '".bat" extension are blocked'),
                ({'filename': '../etc/passwd', 'content_base64': 'AAAA'}, 'path traversal'),
                ({'filename': '..', 'content_base64': 'AAAA'}, 'path traversal'),
                ({'filename': 'a.txt', 'content_base64': 'A=='}, 'not valid base64'),
                ({'filename': 'a.txt', 'content_base64': '!!!!'}, 'not valid base64'),
                ({'filename': 'a.txt', 'content_base64': 'data:text/plain;base64,AAAA'},
                 'not valid base64'),
                ({'filename': 'a.txt', 'content_base64': 'QUJDRA', 'expires_in': '9 weeks'},
                 'expires_in'),
            ]
            for arguments, needle in cases:
                with self.subTest(needle=needle):
                    _, text = self.call_tool('upload_file', arguments, expect_error=True)
                    self.assertIn(needle, text)
                    self.assertNotIn('Traceback', text)
            # Oversized files point at the website instead of touching storage.
            with patch.dict(app.config, MCP_MAX_UPLOAD_BYTES=10):
                _, text = self.call_tool('upload_file', {
                    'filename': 'big.txt',
                    'content_base64': base64.b64encode(b'x' * 100).decode(),
                }, expect_error=True)
                self.assertIn('too large', text)
                self.assertIn('website', text)
                self.assertIn(WEBSITE, text)
            put.assert_not_called()
            self.post.assert_not_called()

    def test_upload_file_strips_directory_components(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            self.mock_blob_upload()
            created = self.tool_json('upload_file', {
                'filename': 'notes/diary/entry.txt',
                'content_base64': base64.b64encode(b'hi').decode(),
            })
        self.assertEqual(created['filename'], 'entry.txt')
        self.assertEqual(created['code'], '00000')

    # ── upload_file: ChatGPT file params (openai/fileParams) ─────────────────

    def _file_ref(self, **extra):
        ref = {'download_url': SIGNED_URL, 'file_id': 'file-abc123'}
        ref.update(extra)
        return ref

    def test_upload_file_fetches_host_file_param_and_creates_share(self):
        payload = b'file param bytes'
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            put = self.mock_blob_upload()
            self.mock_public_dns()
            get = self.mock_file_get(return_value=FakeResponse(
                200, {'Content-Length': str(len(payload))}, [payload]))
            created = self.tool_json('upload_file', {
                'file': self._file_ref(mime_type='text/plain',
                                       file_name='notes/report.txt'),
                'expires_in': '7d',
                'custom_code': 'fileparam',
            })
            # Fetch shape: bare GET, no redirects followed, TLS on, no cookies/auth.
            self.assertEqual(get.call_args.args[0], SIGNED_URL)
            kwargs = get.call_args.kwargs
            self.assertEqual(kwargs['timeout'], (5, 15))
            self.assertTrue(kwargs['stream'])
            self.assertTrue(kwargs['verify'])
            self.assertFalse(kwargs['allow_redirects'])
            self.assertNotIn('cookies', kwargs)
            self.assertNotIn('auth', kwargs)
            self.assertNotIn('Authorization', kwargs['headers'])
            self.assertEqual(get.call_count, 1)
            # Share result: sanitized name, right size/expiry, no signed URL anywhere.
            self.assertEqual(created['code'], 'fileparam')
            self.assertEqual(created['filename'], 'report.txt')
            self.assertEqual(created['size'], len(payload))
            self.assertEqual(datetime.fromisoformat(created['expires_at']).timestamp(),
                             self.now + 604800)
            meta = self.tool_json('get_shared_file', {'code': 'fileparam'})
            self.assertEqual(meta['type'], 'file')
            self.assertEqual(meta['filename'], 'report.txt')
            self.assertEqual(meta['size'], len(payload))
            self.assertEqual(meta['download_url'], WEBSITE + '/download/fileparam')
            combined = json.dumps(created) + json.dumps(meta)
            self.assertNotIn(SIGNED_URL, combined)
            self.assertNotIn('oaiusercontent', combined)
            self.assertNotIn('sig=', combined)
            self.assertNotIn(BLOB_URL, combined)
            self.assertEqual(put.call_count, 1)

    def test_upload_file_file_param_and_base64_are_mutually_exclusive(self):
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        both = {'filename': 'a.txt',
                'content_base64': base64.b64encode(b'x').decode(),
                'file': self._file_ref()}
        _, text = self.call_tool('upload_file', both, expect_error=True)
        self.assertIn('only one of "file"', text)
        # Neither source: both bare shapes get the same guidance (a filename alone
        # is neither a file param nor base64 bytes).
        for arguments, needle in (({}, 'Provide one of "file"'),
                                  ({'filename': 'a.txt'}, 'Provide one of "file"'),
                                  ({'content_base64': 'AAAA'},
                                   'Missing required argument "filename"')):
            with self.subTest(arguments=sorted(arguments)):
                _, text = self.call_tool('upload_file', arguments, expect_error=True)
                self.assertIn(needle, text)
                self.assertNotIn('Traceback', text)
        self.assertEqual(get.call_count, 0)

    def test_upload_file_file_param_rejects_unusable_host_payloads(self):
        # Bare file_id, chat_upload:// (mobile), and malformed shapes: clear errors,
        # no fetch, and never a hint of the signed URL.
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        cases = [
            ('file-abc123', 'did not provide a downloadable file URL'),
            ('chat_upload://image_0', 'did not provide a downloadable file URL'),
            (5, 'did not provide a downloadable file URL'),
            ({}, 'did not provide a downloadable file URL'),
            ({'download_url': None, 'file_id': 'f'}, 'did not provide a downloadable'),
            ({'download_url': '', 'file_id': 'f'}, 'did not provide a downloadable'),
            ({'download_url': 123, 'file_id': 'f'}, '"download_url" must be a string'),
            ({'download_url': ['https://x'], 'file_id': 'f'}, '"download_url" must be a string'),
            (self._file_ref(file_name=5), '"file_name" must be a string'),
            (self._file_ref(mime_type=7), '"mime_type" must be a string'),
            (self._file_ref(file_id=[]), '"file_id" must be a string'),
        ]
        for index, (ref, needle) in enumerate(cases):
            with self.subTest(needle=needle, index=index):
                _, text = self.call_tool('upload_file', {'file': ref},
                                         request_id=index + 1, expect_error=True)
                self.assertIn(needle, text)
                self.assertNotIn('Traceback', text)
                self.assertNotIn('oaiusercontent', text)
                self.assertNotIn('sig=', text)
        # Bad expiry with a file param fails before any download starts.
        _, text = self.call_tool('upload_file',
                                 {'file': self._file_ref(), 'expires_in': '9 weeks'},
                                 request_id=99, expect_error=True)
        self.assertIn('expires_in', text)
        self.assertEqual(get.call_count, 0)

    def test_upload_file_file_param_rejects_unsafe_urls_before_fetch(self):
        # Scheme, userinfo, port, allowlist boundary, and obvious private targets
        # must all be rejected before requests.get is ever called (no DNS either,
        # except where the allowlist itself would trigger it — none of these do).
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        cases = [
            ('http://files.oaiusercontent.com/f', 'must be an https URL'),
            ('ftp://files.oaiusercontent.com/f', 'must be an https URL'),
            ('file:///etc/passwd', 'must be an https URL'),
            ('not-a-url', 'must be an https URL'),
            ('https://127.0.0.1/f', 'not allowed'),
            ('https://localhost/f', 'not allowed'),
            ('https://169.254.169.254/latest/meta-data', 'not allowed'),
            ('https://10.0.0.8/f', 'not allowed'),
            ('https://[::1]/f', 'not allowed'),
            ('https://evil-oaiusercontent.com/f', 'not allowed'),
            ('https://oaiusercontent.com.evil.com/f', 'not allowed'),
            ('https://files.oaiusercontent.com.evil.com/f', 'not allowed'),
            ('https://notoaiusercontent.com/f', 'not allowed'),
            ('https://files.oaiusercontent.com@evil.com/f', 'not allowed'),
            ('https://user:pass@files.oaiusercontent.com/f', 'not allowed'),
            ('https://files.oaiusercontent.com:8443/f', 'must be an https URL'),
        ]
        for index, (url, needle) in enumerate(cases):
            with self.subTest(url=url):
                _, text = self.call_tool('upload_file',
                                         {'file': {'download_url': url, 'file_id': 'f'}},
                                         request_id=index + 1, expect_error=True)
                self.assertIn(needle, text)
                self.assertNotIn('Traceback', text)
                self.assertNotIn('user:pass', text)
                self.assertNotIn('@evil.com', text)
        self.assertEqual(get.call_count, 0)

    def test_upload_file_file_param_dns_failures_fail_closed(self):
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        # DNS failure on an allowlisted host: rejected, no fetch.
        with patch('flask_app.socket.getaddrinfo',
                   side_effect=socket.gaierror(-2, 'Name or service not known')):
            _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                     expect_error=True)
        self.assertIn('not allowed', text)
        # Resolution to a link-local address (DNS rebinding): rejected, no fetch.
        with patch('flask_app.socket.getaddrinfo',
                   return_value=[(socket.AF_INET, socket.SOCK_STREAM,
                                  socket.IPPROTO_TCP, '', ('169.254.169.254', 443))]):
            _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                     request_id=2, expect_error=True)
        self.assertIn('not allowed', text)
        self.assertEqual(get.call_count, 0)

    def test_file_host_rejection_logs_hostname_only(self):
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        url = ('https://files.oaiusercontent.com.evil.com/secret-path'
               '?sig=LEAKME&x=1#frag')
        with self.assertLogs('mcp', level='WARNING') as logs:
            _, text = self.call_tool('upload_file',
                                     {'file': {'download_url': url, 'file_id': 'f'}},
                                     expect_error=True)
        self.assertEqual(len(logs.output), 1)
        line = logs.output[0]
        # One line: the reason code plus the bare, sanitized hostname.
        self.assertIn('(host_not_allowed)', line)
        self.assertIn('files.oaiusercontent.com.evil.com', line)
        for leak in ('https://', '/secret-path', 'sig=', 'LEAKME', 'x=1', '#frag'):
            self.assertNotIn(leak, line)
        # The tool response stays generic as before.
        self.assertIn('not allowed', text)
        self.assertNotIn('files.oaiusercontent', text)
        self.assertNotIn('sig=', text)
        self.assertNotIn('Traceback', text)
        self.assertEqual(get.call_count, 0)

    def test_lookalike_hosts_are_rejected_and_logged_hostname_only(self):
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        lookalikes = [
            'https://evil-oaiusercontent.com/x?sig=LEAK',
            'https://oaiusercontent.com.evil.com/x?sig=LEAK',
            'https://notoaiusercontent.com/x?sig=LEAK',
            'https://files.oaiusercontent.com.cdn.example/x?sig=LEAK',
        ]
        for index, url in enumerate(lookalikes):
            expected_host = url.split('/')[2]
            with self.subTest(url=url):
                with self.assertLogs('mcp', level='WARNING') as logs:
                    _, text = self.call_tool('upload_file',
                                             {'file': {'download_url': url,
                                                       'file_id': 'f'}},
                                             request_id=index + 1,
                                             expect_error=True)
                self.assertEqual(len(logs.output), 1)
                line = logs.output[0]
                self.assertIn('(host_not_allowed)', line)
                self.assertIn(expected_host, line)
                for leak in ('https://', '/x', 'sig=', 'LEAK'):
                    self.assertNotIn(leak, line)
                self.assertIn('not allowed', text)
                self.assertNotIn(expected_host, text)
        self.assertEqual(get.call_count, 0)

    def test_file_redirect_host_rejection_logs_hostname_only(self):
        get = self.mock_file_get(return_value=FakeResponse(
            302, {'Location': 'https://cdn.malicious.example/collect?token=LEAKME'}))
        self.mock_public_dns()
        with self.assertLogs('mcp', level='WARNING') as logs:
            _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                     expect_error=True)
        self.assertEqual(len(logs.output), 1)
        line = logs.output[0]
        self.assertIn('(redirect_host_not_allowed)', line)
        self.assertNotIn('(host_not_allowed)', line)
        self.assertIn('cdn.malicious.example', line)
        for leak in ('https://', '/collect', 'token=', 'LEAKME'):
            self.assertNotIn(leak, line)
        self.assertIn('not allowed', text)
        self.assertNotIn('malicious', text)
        self.assertEqual(get.call_count, 1)

    def test_file_host_suffix_env_override_comma_list_and_dot_boundary(self):
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        public_dns = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                       ('23.22.3.10', 443))]
        with patch.dict(os.environ):
            os.environ.pop('MCP_FILE_HOST_SUFFIXES', None)
            # Defaults stay exactly as documented when the override is absent.
            self.assertEqual(mcp.DEFAULT_FILE_HOST_SUFFIXES,
                             'oaiusercontent.com,openai.com')
            self.assertEqual(mcp._file_host_suffixes(),
                             ('oaiusercontent.com', 'openai.com'))
            # The override is a comma-separated list; spaces are tolerated.
            os.environ['MCP_FILE_HOST_SUFFIXES'] = 'mycdn.example, assets.internal.test'
            self.assertEqual(mcp._file_host_suffixes(),
                             ('mycdn.example', 'assets.internal.test'))
            with patch('flask_app.socket.getaddrinfo', return_value=public_dns):
                for allowed in ('https://files.mycdn.example/f.txt?sig=x',
                                'https://a.assets.internal.test/f.txt'):
                    with self.subTest(allowed=allowed):
                        self.assertEqual(mcp._validate_file_url(allowed), allowed)
                # Strict dot-boundary: suffix lookalikes never match.
                for rejected in ('https://evilmycdn.example/f',
                                 'https://cdn.example/f',
                                 'https://mycdn.example.evil.com/f',
                                 'https://a.assets.internal.test.attacker.io/f'):
                    with self.subTest(rejected=rejected):
                        with self.assertLogs('mcp', level='WARNING') as logs:
                            with self.assertRaises(mcp.ToolError):
                                mcp._validate_file_url(rejected)
                        self.assertEqual(len(logs.output), 1)
                        self.assertIn('(host_not_allowed)', logs.output[0])
                        self.assertNotIn('https://', logs.output[0])
                        self.assertNotIn('/f', logs.output[0])
        self.assertEqual(get.call_count, 0)

    def test_upload_file_file_param_redirects_and_http_failures(self):
        payload = b'redirected bytes'
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            self.mock_blob_upload()
            self.mock_public_dns()
            get = self.mock_file_get()
            scenarios = [
                (FakeResponse(302, {'Location': 'https://169.254.169.254/meta'}),
                 'not allowed', 1),
                (FakeResponse(302, {'Location': 'https://evil.com/steal'}),
                 'not allowed', 1),
                (FakeResponse(302, {'Location': 'http://files.oaiusercontent.com/f'}),
                 'must be an https URL', 1),
                (FakeResponse(302, {'Location': 'https://files.oaiusercontent.com:8443/f'}),
                 'must be an https URL', 1),
                (FakeResponse(302, {}), 'Could not download the attached file', 1),
                (FakeResponse(403, {}), 'HTTP 403', 1),
                (FakeResponse(404, {}), 'HTTP 404', 1),
            ]
            for index, (response, needle, calls) in enumerate(scenarios):
                with self.subTest(needle=needle):
                    get.reset_mock()
                    get.side_effect = None
                    get.return_value = response
                    _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                             request_id=index + 1, expect_error=True)
                    self.assertIn(needle, text)
                    self.assertEqual(get.call_count, calls)
                    self.assertNotIn('evil.com', text)
                    self.assertNotIn('169.254', text)
            # Valid same-host redirect chain is followed (302 -> 200 -> share).
            get.reset_mock()
            get.side_effect = [
                FakeResponse(302, {'Location': SIGNED_URL + '&hop=1'}),
                FakeResponse(200, {'Content-Length': str(len(payload))}, [payload]),
            ]
            created = self.tool_json('upload_file', {'file': self._file_ref()},
                                     request_id=50)
            self.assertEqual(created['size'], len(payload))
            self.assertEqual(get.call_count, 2)
            self.assertNotIn(SIGNED_URL, json.dumps(created))
            # Too many redirects: bounded manual loop, generic error.
            get.reset_mock()
            get.side_effect = None
            get.return_value = FakeResponse(302, {'Location': SIGNED_URL})
            _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                     request_id=51, expect_error=True)
            self.assertIn('too many redirects', text)
            self.assertEqual(get.call_count, 4)
            self.assertNotIn('oaiusercontent', text)

    def test_upload_file_file_param_enforces_size_limit(self):
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            put = self.mock_blob_upload()
            self.mock_public_dns()
            get = self.mock_file_get()
            # Declared Content-Length over the cap: rejected without reading the body.
            with patch.dict(app.config, MCP_MAX_UPLOAD_BYTES=100):
                oversize = FakeResponse(200, {'Content-Length': '9999'}, chunks=[b'x'])
                get.return_value = oversize
                _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                         expect_error=True)
                self.assertIn('too large', text)
                self.assertIn(WEBSITE, text)
                self.assertFalse(oversize.iter_called)
            # Mid-body overflow: stream stops as soon as the cap is passed.
            get.reset_mock()
            with patch.dict(app.config, MCP_MAX_UPLOAD_BYTES=10):
                stream = FakeResponse(200, {'Content-Length': '10'},
                                      chunks=[b'x' * 8, b'x' * 8])
                get.return_value = stream
                _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                         request_id=2, expect_error=True)
                self.assertIn('too large', text)
                self.assertTrue(stream.iter_called)
            put.assert_not_called()
            # A body exactly at the cap still uploads.
            get.reset_mock()
            exact = FakeResponse(200, {'Content-Length': '10'}, chunks=[b'x' * 10])
            get.return_value = exact
            with patch.dict(app.config, MCP_MAX_UPLOAD_BYTES=10):
                created = self.tool_json('upload_file',
                                         {'file': self._file_ref()},
                                         request_id=3)
            self.assertEqual(created['size'], 10)
            self.assertEqual(put.call_count, 1)
            self.assertEqual(get.call_count, 1)

    def test_upload_file_file_param_network_errors_are_generic(self):
        get = self.mock_file_get(side_effect=requests.Timeout('connect timeout'))
        with self.assertLogs('mcp', level='WARNING') as logs:
            _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                     expect_error=True)
        self.assertIn('timed out', text)
        self.assertNotIn('oaiusercontent', text)
        self.assertNotIn('connect timeout', text)
        self.assertNotIn('sig=', text)
        self.assertTrue(any('Timeout' in line for line in logs.output))
        self.assertTrue(all('oaiusercontent' not in line for line in logs.output))
        # Connection failures: generic response, exception type only in the log.
        get.side_effect = requests.ConnectionError('proxy refused connection')
        get.reset_mock()
        with self.assertLogs('mcp', level='WARNING') as logs2:
            _, text = self.call_tool('upload_file', {'file': self._file_ref()},
                                     request_id=2, expect_error=True)
        self.assertIn('Could not download the attached file', text)
        self.assertNotIn('proxy refused', text)
        self.assertNotIn('oaiusercontent', text)
        self.assertNotIn('Traceback', text)
        self.assertTrue(any('ConnectionError' in line for line in logs2.output))
        self.assertTrue(all('oaiusercontent' not in line for line in logs2.output))
        self.assertEqual(get.call_count, 1)

    def test_upload_file_file_param_sanitizes_and_blocks_filenames(self):
        get = self.mock_file_get(side_effect=AssertionError('fetch must not run'))
        cases = [
            ('evil.exe', '".exe" extension are blocked'),
            ('evil.bat', '".bat" extension are blocked'),
            ('../etc/passwd', 'path traversal'),
            ('..', 'path traversal'),
        ]
        for index, (name, needle) in enumerate(cases):
            with self.subTest(name=name):
                _, text = self.call_tool('upload_file',
                                         {'file': self._file_ref(file_name=name)},
                                         request_id=index + 1, expect_error=True)
                self.assertIn(needle, text)
                self.assertNotIn('Traceback', text)
        self.assertEqual(get.call_count, 0)
        # Directory components are stripped on the success path too.
        get.side_effect = None
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            self.mock_blob_upload()
            self.mock_public_dns()
            get.return_value = FakeResponse(200, {'Content-Length': '2'}, [b'hi'])
            created = self.tool_json('upload_file',
                                     {'file': self._file_ref(file_name='notes/diary/entry.txt')},
                                     request_id=50)
        self.assertEqual(created['filename'], 'entry.txt')
        self.assertEqual(created['size'], 2)
        # A missing/blank file_name falls back to a generic name.
        get.reset_mock()
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            self.mock_blob_upload()
            self.mock_public_dns()
            get.return_value = FakeResponse(200, {'Content-Length': '2'}, [b'hi'])
            created = self.tool_json('upload_file',
                                     {'file': {'download_url': SIGNED_URL,
                                               'file_id': 'file-abc123',
                                               'file_name': '   '}},
                                     request_id=51)
        self.assertEqual(created['filename'], 'attachment')
        self.assertNotIn(SIGNED_URL, json.dumps(created))

    def test_duplicate_custom_code_is_a_clear_tool_error(self):
        created = self.tool_json('share_text', {'text': 'first', 'custom_code': 'dupcode'})
        self.assertEqual(created['code'], 'dupcode')
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN):
            self.mock_blob_upload()
            _, text = self.call_tool('upload_file', {
                'filename': 'again.txt',
                'content_base64': base64.b64encode(b'x').decode(),
                'custom_code': 'dupcode',
            }, expect_error=True)
        self.assertIn('already taken', text)
        # The original share is untouched.
        content = self.tool_json('get_shared_content', {'code': 'dupcode'})
        self.assertEqual(content['text'], 'first')

    def test_unknown_tool_lists_the_available_ones(self):
        _, text = self.call_tool('delete_all_shares', {}, expect_error=True)
        self.assertIn('Unknown tool', text)
        for name in ('upload_file', 'share_text', 'get_shared_content',
                     'get_shared_file', 'check_share'):
            self.assertIn(name, text)

    # ── read tools ───────────────────────────────────────────────────────────

    def test_missing_and_expired_shares_report_one_uniform_message(self):
        _, text_missing = self.call_tool('get_shared_content', {'code': '77777'},
                                         expect_error=True)
        _, text_missing_file = self.call_tool('get_shared_file', {'code': '77777'},
                                              expect_error=True)
        self.assertEqual(text_missing, 'Share not found or expired.')
        self.assertEqual(text_missing_file, text_missing)
        self.create_share(kind='text', name='Shared Text', size=5,
                          expires=self.now - 60, content='stale')
        _, text_expired = self.call_tool('get_shared_content', {'code': '00000'},
                                         expect_error=True)
        _, text_expired_file = self.call_tool('get_shared_file', {'code': '00000'},
                                              expect_error=True)
        self.assertEqual(text_expired, 'Share not found or expired.')
        self.assertEqual(text_expired_file, 'Share not found or expired.')

    def test_invalid_share_codes_are_rejected_by_pattern(self):
        for code in ('ab', 'x' * 21, 'has space', 'bad!', '5/../..', ''):
            with self.subTest(code=code):
                _, text = self.call_tool('get_shared_content', {'code': code},
                                         expect_error=True)
                self.assertIn('Invalid share code', text)

    def test_check_share_reports_present_missing_and_expired(self):
        result = self.tool_json('check_share', {'code': '99999'})
        self.assertEqual(result, {'exists': False})
        self.create_share(kind='file', name='photo.png', size=42,
                          expires=self.now + 3600, url=FILE_URL, provider='litterbox')
        result = self.tool_json('check_share', {'code': '00000'})
        self.assertTrue(result['exists'])
        self.assertFalse(result['expired'])
        self.assertEqual(result['type'], 'file')
        self.assertEqual(result['filename'], 'photo.png')
        self.assertEqual(result['size'], 42)
        self.assertFalse(result['is_encrypted'])
        self.assertEqual(datetime.fromisoformat(result['expires_at']).timestamp(),
                         self.now + 3600)
        # An expired row still exists but is flagged as expired.
        self.create_share(kind='text', name='Shared Text', size=3,
                          expires=self.now - 5, content='gone')
        result = self.tool_json('check_share', {'code': '00001'})
        self.assertTrue(result['exists'])
        self.assertTrue(result['expired'])

    def test_encrypted_shares_never_expose_ciphertext_or_key_material(self):
        ciphertext = 'U2FsdGVkX1+not-really-encrypted-but-looks-it'
        response = self.client.post('/upload', data={
            'mode': 'text', 'text': ciphertext, 'expire': '1h',
            'isEncrypted': '1', 'salt': 'saltySaltValue', 'iv': 'ivValue123',
        })
        self.assertEqual(response.status_code, 200)
        key = response.get_json()['uploads'][0]['key']
        for tool in ('get_shared_content', 'get_shared_file', 'check_share'):
            with self.subTest(tool=tool):
                response, payload = self.rpc('tools/call',
                                             {'name': tool, 'arguments': {'code': key}})
                raw = response.get_data(as_text=True)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('saltySaltValue', raw)
                self.assertNotIn('ivValue123', raw)
                self.assertNotIn(ciphertext, raw)
                data = json.loads(payload['result']['content'][0]['text'])
                self.assertTrue(data['is_encrypted'])
                if tool == 'check_share':
                    continue
                self.assertEqual(data['type'], 'text')
                self.assertNotIn('text', data)
                self.assertNotIn('content', data)
                self.assertNotIn('salt', data)
                self.assertNotIn('iv', data)
                self.assertIn('browser', data['message'])
                self.assertIn('password', data['message'].lower())

    def test_folder_share_returns_file_listing_only(self):
        self.create_share(kind='folder', name='Project Files', size=99,
                          expires=self.now + 3600,
                          content=json.dumps([{'name': 'a.txt', 'size': 5},
                                              {'name': 'b.pdf', 'size': 7}]))
        content = self.tool_json('get_shared_content', {'code': '00000'})
        self.assertEqual(content['type'], 'folder')
        self.assertEqual(content['file_count'], 2)
        self.assertEqual(content['files'], [{'name': 'a.txt', 'size': 5},
                                            {'name': 'b.pdf', 'size': 7}])
        self.assertFalse(content['is_encrypted'])

    def test_large_or_binary_files_never_return_inline_content(self):
        self.create_share(kind='file', name='huge.txt', size=200_000,
                          expires=self.now + 3600, url=FILE_URL, provider='litterbox')
        content = self.tool_json('get_shared_content', {'code': '00000'})
        self.assertFalse(content['content_available'])
        self.assertNotIn('text', content)
        self.assertIn('download_url', content['message'])
        self.create_share(kind='file', name='photo.png', size=10,
                          expires=self.now + 3600, url=FILE_URL, provider='litterbox')
        content = self.tool_json('get_shared_content', {'code': '00001'})
        self.assertFalse(content['content_available'])
        self.assertNotIn('text', content)

    # ── auth and gating ──────────────────────────────────────────────────────

    def test_bearer_api_key_is_enforced_with_clear_protocol_errors(self):
        with patch.dict(app.config, MCP_API_KEY='correct-horse-key'):
            response, payload = self.rpc('ping', request_id=5)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(payload['error']['code'], -32001)
            self.assertEqual(payload['error']['message'],
                             'Unauthorized: send Authorization: Bearer <MCP_API_KEY>.')
            self.assertEqual(payload['id'], 5)
            self.assertEqual(response.headers['WWW-Authenticate'], 'Bearer')
            for header in ('Bearer wrong-key', 'wrong-key', 'bearer correct-horse-key'):
                with self.subTest(header=header):
                    response, _ = self.rpc('ping', request_id=6,
                                           headers={'Authorization': header})
                    self.assertEqual(response.status_code, 401)
            response, payload = self.rpc('ping', request_id=7,
                                         headers={'Authorization': 'Bearer correct-horse-key'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(payload['result'], {})

    def test_disabled_endpoint_is_a_plain_404(self):
        with patch.dict(app.config, MCP_ENABLED=False):
            response = self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.get_json(), {'error': 'Not found.'})
            response = self.client.get('/mcp')
            self.assertEqual(response.status_code, 404)
            response = self.client.options('/mcp')
            self.assertEqual(response.status_code, 404)

    # ── HTTP-level rules ─────────────────────────────────────────────────────

    def test_get_content_type_and_origin_rules(self):
        response = self.client.get('/mcp')
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.headers['Allow'], 'POST')
        self.assertEqual(response.get_json()['error']['code'], -32600)
        response = self.client.post('/mcp', data='mode=text', content_type='text/plain')
        self.assertEqual(response.status_code, 415)
        self.assertIn('application/json', response.get_json()['error']['message'])
        response = self.client.post('/mcp',
                                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                                    headers={'Origin': 'https://evil.example'})
        self.assertEqual(response.status_code, 403)
        self.assertIn('Origin', response.get_json()['error']['message'])
        response = self.client.post('/mcp',
                                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                                    headers={'Origin': 'https://chatgpt.com'})
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/mcp',
                                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                                    headers={'Origin': 'https://chat.openai.com'})
        self.assertEqual(response.status_code, 200)

    def test_jsonrpc_parse_and_validation_errors(self):
        response = self.client.post('/mcp', data='{"jsonrpc": "2.0",',
                                    content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error']['code'], -32700)
        response = self.client.post('/mcp', data='[1, 2, 3]',
                                    content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error']['code'], -32600)
        response = self.client.post('/mcp', json={'jsonrpc': '1.0', 'id': 3, 'method': 'ping'})
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertEqual(payload['error']['code'], -32600)
        self.assertIn('jsonrpc', payload['error']['message'])
        response = self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 4, 'method': 7})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error']['code'], -32600)
        response = self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 5})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error']['code'], -32600)
        response = self.client.post('/mcp', json={'id': 6, 'method': 'ping'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error']['code'], -32600)
        # tools/call parameter problems are -32602 with the id preserved.
        for params in ('share_text', {'name': 5}, {'name': 'ping', 'arguments': []},
                       {'arguments': {}}):
            with self.subTest(params=params):
                response, payload = self.rpc('tools/call', params, request_id=11)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(payload['error']['code'], -32602)
                self.assertEqual(payload['id'], 11)

    def test_body_size_limit_returns_jsonrpc_413(self):
        with patch.dict(app.config, MCP_MAX_UPLOAD_BYTES=10):
            body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","pad":"' + b'x' * 70_000 + b'"}'
            response = self.client.post('/mcp', data=body, content_type='application/json')
        self.assertEqual(response.status_code, 413)
        payload = response.get_json()
        self.assertEqual(payload['error']['code'], -32600)
        self.assertIn('too large', payload['error']['message'])

    def test_database_failure_stays_jsonrpc_and_leaks_nothing(self):
        with patch('flask_app.get_db', side_effect=sqlite3.OperationalError('disk I/O error')):
            response, payload = self.rpc('tools/list', request_id=11)
        self.assertEqual(response.status_code, 503)
        raw = response.get_data(as_text=True)
        self.assertEqual(payload['error']['code'], -32603)
        self.assertEqual(payload['id'], 11)
        self.assertNotIn('disk I/O error', raw)
        self.assertNotIn('Traceback', raw)
        self.assertNotIn('OperationalError', raw)

    # ── rate limiting ────────────────────────────────────────────────────────

    def test_mcp_write_bucket_limits_and_window_reset(self):
        with patch.dict(app.config, MCP_RATE_LIMIT=1):
            response, payload = self.rpc('tools/list', request_id=1)
            self.assertEqual(response.status_code, 200)
            response, payload = self.rpc('tools/list', request_id=2)
            self.assertEqual(response.status_code, 429)
            self.assertEqual(payload['error']['code'], -32005)
            self.assertEqual(payload['id'], 2)
            retry = int(response.headers['Retry-After'])
            self.assertGreaterEqual(retry, 595)
            self.assertLessEqual(retry, 601)
            # The read bucket keeps working while writes are throttled.
            _, text = self.call_tool('check_share', {'code': '12345'}, request_id=3,
                                     expect_error=False)
            self.assertEqual(json.loads(text), {'exists': False})
            with app.app_context():
                actions = sorted(row[0] for row in
                                 get_db().execute('SELECT action FROM rate_limits').fetchall())
            self.assertEqual(actions, ['mcp', 'mcp_lookup'])
            # Once the window passes, the bucket resets.
            self.clock.return_value = self.now + 600
            response, _ = self.rpc('tools/list', request_id=4)
            self.assertEqual(response.status_code, 200)

    def test_mcp_lookup_bucket_is_stricter_and_separate(self):
        with patch.dict(app.config, MCP_LOOKUP_RATE_LIMIT=1):
            response, _ = self.rpc('tools/call', {'name': 'check_share',
                                                  'arguments': {'code': '12345'}}, request_id=1)
            self.assertEqual(response.status_code, 200)
            response, payload = self.rpc('tools/call', {'name': 'check_share',
                                                        'arguments': {'code': '12345'}},
                                         request_id=2)
            self.assertEqual(response.status_code, 429)
            self.assertEqual(payload['error']['code'], -32005)
            self.assertIn('Retry-After', response.headers)
            # Writes live in their own bucket and are unaffected.
            created = self.tool_json('share_text', {'text': 'still allowed'}, request_id=3)
            self.assertTrue(created['success'])

    # ── secret hygiene ───────────────────────────────────────────────────────

    def test_responses_never_leak_secrets_paths_or_tracebacks(self):
        bodies = []
        response, _ = self.rpc('initialize', request_id=1)
        bodies.append(response.get_data(as_text=True))
        response, _ = self.rpc('tools/list', request_id=2)
        bodies.append(response.get_data(as_text=True))
        with patch.dict(app.config, BLOB_READ_WRITE_TOKEN=BLOB_TOKEN,
                        LITTERBOX_PROXY_SECRET='proxy-secret-value'), \
                patch('flask_app.requests.put') as put:
            put.return_value.__enter__.return_value.status_code = 200
            put.return_value.__enter__.return_value.json.return_value = {'url': BLOB_URL}
            response, _ = self.rpc('tools/call', {
                'name': 'upload_file',
                'arguments': {'filename': 'leak.txt',
                              'content_base64': base64.b64encode(b'leaky').decode(),
                              'custom_code': 'leakcheck'},
            }, request_id=3)
            bodies.append(response.get_data(as_text=True))
            upstream = requests.Response()
            upstream.status_code = 200
            upstream._content = b'leaky'
            upstream._content_consumed = True
            upstream.headers['Content-Type'] = 'text/plain'
            with patch('flask_app.requests.get') as get:
                get.return_value = upstream
                for tool, arguments in (('get_shared_file', {'code': 'leakcheck'}),
                                        ('get_shared_content', {'code': 'leakcheck'}),
                                        ('check_share', {'code': 'leakcheck'}),
                                        ('get_shared_content', {'code': '00000'})):
                    response, _ = self.rpc('tools/call', {'name': tool, 'arguments': arguments},
                                           request_id=4)
                    bodies.append(response.get_data(as_text=True))
        response, _ = self.rpc('tools/list', request_id=5)
        bodies.append(response.get_data(as_text=True))
        response = self.client.post('/mcp', data='{broken', content_type='application/json')
        bodies.append(response.get_data(as_text=True))
        response = self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                                    headers={'Origin': 'https://evil.example'})
        bodies.append(response.get_data(as_text=True))
        forbidden = [BLOB_TOKEN, BLOB_URL, 'proxy-secret-value', 'shares.sqlite3',
                     str(Path(self.database).parent), 'DATABASE_URL', 'Traceback',
                     'OperationalError', 'private.blob.vercel-storage.com']
        for body in bodies:
            self.assertTrue(body)
            for needle in forbidden:
                with self.subTest(needle=needle):
                    self.assertNotIn(needle, body)
        with patch.dict(app.config, MCP_API_KEY='sekret-key-value'):
            response, _ = self.rpc('ping', request_id=6)
            self.assertNotIn('sekret-key-value', response.get_data(as_text=True))
            response = self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 7, 'method': 'ping'},
                                        headers={'Authorization': 'Bearer sekret-key-value'})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('sekret-key-value', response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
