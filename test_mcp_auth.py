"""Regression tests for MCP authentication posture.

The MCP endpoint must never silently serve tools to anonymous callers:
it either has a configured credential (OAuth owner account or a static API
key), refuses the request, or runs in the explicit opt-in development mode.
"""
import base64
import html as html_lib
import json
import re
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from flask_app import app, get_db
from oauth.security import hash_password, pkce_challenge

OWNER = 'owner'
OWNER_PASSWORD = 'correct-horse-battery-staple'
REDIRECT = 'https://client.example/callback'
ISSUER = 'https://example.test'
AUDIENCE = ISSUER + '/mcp'
RESOURCE_METADATA = ISSUER + '/.well-known/oauth-protected-resource'
READ_SCOPE = 'alienxfile:read'
WRITE_SCOPE = 'alienxfile:write'


class McpAuthTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='alienx-mcp-auth-test-')
        self.addCleanup(directory.cleanup)
        self.database = str(Path(directory.name) / 'mcp-auth.sqlite3')
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(app.config, **{
            'TESTING': True,
            'DATABASE': self.database,
            'DATABASE_URL': None,
            'BLOB_READ_WRITE_TOKEN': '',
            'SECRET_KEY': 'mcp-auth-test-secret',
            'MCP_ENABLED': True,
            'MCP_API_KEY': '',
            'MCP_ALLOW_ANONYMOUS': False,
            'MCP_ALLOW_ANONYMOUS_WRITES': False,
            'MCP_OAUTH_ENABLED': True,
            'OAUTH_ENABLED': True,
            'OAUTH_OWNER_CONFIGURED': True,
            'OAUTH_ISSUER': ISSUER,
            'OAUTH_AUDIENCE': AUDIENCE,
            'OWNER_USERNAME': OWNER,
            'OWNER_PASSWORD_HASH': hash_password(OWNER_PASSWORD),
            'OAUTH_ACCESS_TOKEN_TTL': 900,
            'OAUTH_REFRESH_TOKEN_TTL': 2_592_000,
            'OAUTH_CODE_TTL': 300,
            'OAUTH_SESSION_TTL': 43_200,
            'OAUTH_LOGIN_WINDOW': 900,
            'OAUTH_DCR_ENABLED': True,
            'OAUTH_CIMD_ENABLED': True,
            'OAUTH_COOKIE_SECURE': False,
            'OAUTH_AUTHORIZE_RATE_LIMIT': 1000,
            'OAUTH_TOKEN_RATE_LIMIT': 1000,
            'OAUTH_REGISTER_RATE_LIMIT': 1000,
            'OAUTH_REVOKE_RATE_LIMIT': 1000,
            'OAUTH_ACCOUNT_RATE_LIMIT': 1000,
            'LOGIN_RATE_LIMIT': 1000,
            'RATE_WINDOW_SECONDS': 600,
            'UPLOAD_RATE_LIMIT': 1000,
            'LOOKUP_RATE_LIMIT': 1000,
            'MCP_RATE_LIMIT': 1000,
            'MCP_LOOKUP_RATE_LIMIT': 1000,
            'MCP_RATE_WINDOW': 600,
            'MCP_MAX_UPLOAD_BYTES': 5_242_880,
            'MCP_DAILY_BYTES_PER_IP': 52_428_800,
            'MCP_GLOBAL_DAILY_BYTES': 314_572_800,
            'MCP_DAILY_BYTES_WINDOW': 86_400,
            'MCP_ALLOWED_ORIGINS': 'https://chatgpt.com',
            'MCP_PUBLIC_BASE_URL': ISSUER,
            'MAX_TEXT_LENGTH': 100_000,
            'TRUST_PYTHONANYWHERE_PROXY': False,
            'TRUST_RENDER_PROXY': False,
        }))
        self.stack.enter_context(patch(
            'requests.sessions.Session.request',
            side_effect=AssertionError('Unexpected outbound request')))
        with app.app_context():
            get_db()
        self.client = app.test_client()

    # ── helpers ─────────────────────────────────────────────────────────────

    def rpc(self, method, params=None, headers=None, request_id=1):
        body = {'jsonrpc': '2.0', 'id': request_id, 'method': method}
        if params is not None:
            body['params'] = params
        response = self.client.post('/mcp', json=body, headers=headers or {})
        return response, response.get_json(silent=True)

    def call_tool(self, name, arguments=None, headers=None):
        return self.rpc('tools/call', {'name': name, 'arguments': arguments or {}}, headers=headers)

    @staticmethod
    def _fields(page):
        return {name: html_lib.unescape(value) for name, value in
                re.findall(r'name="([^"]+)" value="([^"]*)"', page)}

    def _login(self, next_url='/account'):
        page = self.client.get('/login', query_string={'next': next_url})
        self.assertEqual(page.status_code, 200)
        fields = self._fields(page.get_data(as_text=True))
        response = self.client.post('/login', data={
            'csrf_token': fields['csrf_token'],
            'next': fields['next'],
            'username': OWNER,
            'password': OWNER_PASSWORD,
        })
        self.assertEqual(response.status_code, 303)

    def access_token(self, scope=f'{READ_SCOPE} {WRITE_SCOPE}'):
        """Run the full owner browser flow and return an access token."""
        registered = self.client.post('/oauth/register', json={
            'client_name': 'Auth Regression Client',
            'redirect_uris': [REDIRECT],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
            'scope': scope,
        })
        self.assertEqual(registered.status_code, 201, registered.get_data(as_text=True))
        client_id = registered.get_json()['client_id']
        verifier = base64.urlsafe_b64encode(b'v' * 32).rstrip(b'=').decode()
        params = {
            'client_id': client_id,
            'redirect_uri': REDIRECT,
            'response_type': 'code',
            'code_challenge': pkce_challenge(verifier),
            'code_challenge_method': 'S256',
            'scope': scope,
            'state': 'regression-state',
            'resource': AUDIENCE,
        }
        response = self.client.get('/oauth/authorize', query_string=params)
        if response.status_code == 303:
            location = response.headers['Location']
            next_value = parse_qs(urlparse(location).query).get('next', ['/account'])[0]
            self._login(next_value)
            response = self.client.get(next_value)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:400])
        fields = self._fields(response.get_data(as_text=True))
        approved = self.client.post('/oauth/authorize', data={
            **{key: value for key, value in fields.items() if key != 'csrf_token'},
            'csrf_token': fields['csrf_token'],
            'decision': 'approve',
        })
        self.assertEqual(approved.status_code, 302, approved.get_data(as_text=True)[:400])
        code = parse_qs(urlparse(approved.headers['Location']).query)['code'][0]
        token = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT,
            'client_id': client_id,
            'code_verifier': verifier,
            'resource': AUDIENCE,
        })
        self.assertEqual(token.status_code, 200, token.get_data(as_text=True))
        return token.get_json()['access_token']

    def _share_count(self):
        with app.app_context():
            row = get_db().execute('SELECT COUNT(*) AS total FROM shares').fetchone()
            return row['total']

    # ── 1. MCP disabled ─────────────────────────────────────────────────────

    def test_mcp_disabled_exposes_no_tools(self):
        with patch.dict(app.config, MCP_ENABLED=False):
            response, body = self.rpc('tools/list')
            self.assertEqual(response.status_code, 404)
            self.assertNotIn('result', body or {})
            self.assertNotIn('tools', (body or {}).get('result', {}))

    # ── 2. No owner configured and no API key ───────────────────────────────

    def test_no_owner_and_no_api_key_refuses_instead_of_serving_anonymously(self):
        with patch.dict(app.config, OAUTH_OWNER_CONFIGURED=False, MCP_API_KEY=''):
            response, body = self.rpc('tools/list')
            self.assertEqual(response.status_code, 503)
            self.assertEqual(body['error']['code'], -32003)
            self.assertIn('OWNER_PASSWORD_HASH', body['error']['message'])
            self.assertIn('MCP_API_KEY', body['error']['message'])
            self.assertNotIn('result', body)

            response, body = self.call_tool('share_text', {'text': 'anonymous write'})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('result', body)
            self.assertEqual(self._share_count(), 0, 'no share may be created anonymously')

    def test_no_owner_configured_but_api_key_present_requires_the_key(self):
        with patch.dict(app.config, OAUTH_OWNER_CONFIGURED=False, MCP_API_KEY='static-key'):
            denied, body = self.rpc('tools/list')
            self.assertEqual(denied.status_code, 401)
            self.assertEqual(body['error']['code'], -32001)
            self.assertEqual(denied.headers['WWW-Authenticate'], 'Bearer')
            allowed, body = self.rpc('tools/list',
                                     headers={'Authorization': 'Bearer static-key'})
            self.assertEqual(allowed.status_code, 200)
            self.assertIn('tools', body['result'])

    # ── 3. No bearer token ──────────────────────────────────────────────────

    def test_request_without_bearer_token_is_rejected_with_a_challenge(self):
        response, body = self.rpc('tools/list')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body['error']['code'], -32001)
        challenge = response.headers['WWW-Authenticate']
        self.assertTrue(challenge.startswith('Bearer '), challenge)
        self.assertIn(f'resource_metadata="{RESOURCE_METADATA}"', challenge)
        self.assertNotIn('result', body)

        response, body = self.call_tool('share_text', {'text': 'no token'})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('result', body)
        self.assertEqual(self._share_count(), 0)

    # ── 4. Invalid bearer token ─────────────────────────────────────────────

    def test_invalid_bearer_token_is_rejected(self):
        response, body = self.rpc('tools/list',
                                  headers={'Authorization': 'Bearer not-a-real-token'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body['error']['code'], -32001)
        self.assertIn('invalid_token', response.headers['WWW-Authenticate'])
        self.assertNotIn('result', body)

    def test_malformed_authorization_header_is_rejected(self):
        for header in ('Bearer ', 'Basic abc', 'not-a-scheme token'):
            response, body = self.rpc('tools/list', headers={'Authorization': header})
            self.assertEqual(response.status_code, 401, header)
            self.assertEqual(body['error']['code'], -32001)
            self.assertTrue(response.headers['WWW-Authenticate'].startswith('Bearer '))
            self.assertNotIn('result', body)

    def test_revoked_access_token_is_rejected(self):
        token = self.access_token()
        headers = {'Authorization': 'Bearer ' + token}
        allowed, _ = self.rpc('tools/list', headers=headers)
        self.assertEqual(allowed.status_code, 200)
        with app.app_context():
            from oauth.store import revoke_token
            revoke_token(token, _client_id_for(token))
        denied, body = self.rpc('tools/list', headers=headers)
        self.assertEqual(denied.status_code, 401)
        self.assertIn('invalid_token', denied.headers['WWW-Authenticate'])
        self.assertNotIn('result', body)

    # ── 5. Valid token with insufficient scope ──────────────────────────────

    def test_valid_token_with_insufficient_scope_is_forbidden(self):
        token = self.access_token(scope=READ_SCOPE)
        headers = {'Authorization': 'Bearer ' + token}
        response, body = self.call_tool('share_text', {'text': 'blocked'}, headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(body['error']['code'], -32001)
        challenge = response.headers['WWW-Authenticate']
        self.assertIn('insufficient_scope', challenge)
        self.assertIn(WRITE_SCOPE, challenge)
        self.assertEqual(self._share_count(), 0)

        # The read tools stay available for a read-only token.
        response, body = self.call_tool('check_share', {'code': 'abc12'}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('error', body)
        payload = json.loads(body['result']['content'][0]['text'])
        self.assertFalse(payload['exists'])

    # ── 6. Valid token with the correct scope ───────────────────────────────

    def test_valid_token_with_correct_scope_can_use_write_tools(self):
        token = self.access_token(scope=f'{READ_SCOPE} {WRITE_SCOPE}')
        headers = {'Authorization': 'Bearer ' + token}
        response, body = self.call_tool('share_text', {'text': 'authorized write'},
                                        headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(body['result']['isError'])
        payload = json.loads(body['result']['content'][0]['text'])
        self.assertTrue(payload['success'])
        self.assertEqual(self._share_count(), 1)

    # ── explicit anonymous development mode ─────────────────────────────────

    def test_anonymous_opt_in_is_read_only(self):
        # The anonymous development mode only applies when no OAuth owner
        # account is configured; with an owner, OAuth stays mandatory.
        with patch.dict(app.config, MCP_ALLOW_ANONYMOUS=True, MCP_ALLOW_ANONYMOUS_WRITES=False,
                        OAUTH_OWNER_CONFIGURED=False):
            response, body = self.rpc('tools/list')
            self.assertEqual(response.status_code, 200)
            self.assertIn('tools', body['result'])
            response, body = self.call_tool('share_text', {'text': 'blocked'})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(body['error']['code'], -32001)
            self.assertEqual(self._share_count(), 0)
            response, body = self.call_tool('check_share', {'code': 'abc12'})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('error', body)
            payload = json.loads(body['result']['content'][0]['text'])
            self.assertFalse(payload['exists'])

    def test_anonymous_opt_in_does_not_bypass_a_configured_owner(self):
        with patch.dict(app.config, MCP_ALLOW_ANONYMOUS=True, MCP_ALLOW_ANONYMOUS_WRITES=True):
            response, body = self.rpc('tools/list')
            self.assertEqual(response.status_code, 401)
            self.assertNotIn('result', body)

    def test_anonymous_opt_in_can_allow_writes_explicitly(self):
        with patch.dict(app.config, MCP_ALLOW_ANONYMOUS=True, MCP_ALLOW_ANONYMOUS_WRITES=True,
                        OAUTH_OWNER_CONFIGURED=False):
            response, body = self.call_tool('share_text', {'text': 'dev mode write'})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(body['result']['isError'])


def _client_id_for(token):
    """Look up the client that owns an access token (test helper)."""
    from oauth.store import get_access_token
    row = get_access_token(token)
    return row['client_id'] if row else ''


if __name__ == '__main__':
    unittest.main()
