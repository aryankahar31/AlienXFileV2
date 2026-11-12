import base64
import html as html_lib
import re
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from flask_app import app, get_db
from oauth.security import hash_password, pkce_challenge
from oauth.store import validate_access_token

OWNER = 'owner'
OWNER_HASH = hash_password('correct-horse-battery-staple')
REDIRECT_A = 'https://alpha.example/callback'
REDIRECT_B = 'https://beta.example/callback'
ISSUER = 'https://example.test'
AUDIENCE = 'https://example.test/mcp'


class MultiClientTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='alienx-multiclient-test-')
        self.addCleanup(directory.cleanup)
        self.database = str(Path(directory.name) / 'oauth.sqlite3')
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(app.config, **{
            'TESTING': True,
            'DATABASE': self.database,
            'DATABASE_URL': None,
            'SECRET_KEY': 'multiclient-secret',
            'OAUTH_ENABLED': True,
            'OAUTH_ISSUER': ISSUER,
            'OAUTH_AUDIENCE': AUDIENCE,
            'OAUTH_OWNER_CONFIGURED': True,
            'OWNER_USERNAME': OWNER,
            'OWNER_PASSWORD_HASH': OWNER_HASH,
            'OAUTH_ACCESS_TOKEN_TTL': 900,
            'OAUTH_REFRESH_TOKEN_TTL': 2592000,
            'OAUTH_CODE_TTL': 300,
            'OAUTH_SESSION_TTL': 43200,
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
            'MCP_ENABLED': True,
            'MCP_OAUTH_ENABLED': True,
            'MCP_API_KEY': '',
            'MCP_MAX_UPLOAD_BYTES': 5_242_880,
            'MCP_RATE_LIMIT': 1000,
            'MCP_LOOKUP_RATE_LIMIT': 1000,
            'MCP_RATE_WINDOW': 600,
            'MCP_DAILY_BYTES_PER_IP': 52_428_800,
            'MCP_GLOBAL_DAILY_BYTES': 314_572_800,
            'MCP_DAILY_BYTES_WINDOW': 86_400,
            'MCP_ALLOWED_ORIGINS': 'https://chatgpt.com',
            'MCP_PUBLIC_BASE_URL': ISSUER,
            'MAX_TEXT_LENGTH': 100_000,
            'UPLOAD_RATE_LIMIT': 1000,
            'LOOKUP_RATE_LIMIT': 1000,
            'TRUST_PYTHONANYWHERE_PROXY': False,
            'TRUST_RENDER_PROXY': False,
        }))
        self.stack.enter_context(patch(
            'requests.sessions.Session.request',
            side_effect=AssertionError('Unexpected outbound request')))
        with app.app_context():
            get_db()
        self.client = app.test_client()

    @staticmethod
    def _fields(page):
        return {name: html_lib.unescape(value) for name, value in
                re.findall(r'name="([^"]+)" value="([^"]*)"', page)}

    def register(self, name, redirect_uri, scope='alienxfile:read alienxfile:write'):
        response = self.client.post('/oauth/register', json={
            'client_name': name,
            'redirect_uris': [redirect_uri],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
            'scope': scope,
        })
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()['client_id']

    def login(self):
        page = self.client.get('/login', query_string={'next': '/account'})
        if page.status_code == 303:
            return
        fields = self._fields(page.get_data(as_text=True))
        response = self.client.post('/login', data={
            'csrf_token': fields['csrf_token'], 'next': fields['next'],
            'username': OWNER, 'password': 'correct-horse-battery-staple'})
        self.assertEqual(response.status_code, 303)

    def authorization_code(self, client_id, redirect_uri, scope, state):
        verifier = base64.urlsafe_b64encode(b'k' * 32).rstrip(b'=').decode()
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'code_challenge': pkce_challenge(verifier),
            'code_challenge_method': 'S256',
            'scope': scope,
            'state': state,
            'resource': AUDIENCE,
        }
        response = self.client.get('/oauth/authorize', query_string=params)
        if response.status_code == 303 and response.headers['Location'].startswith('/login'):
            self.login()
            response = self.client.get('/oauth/authorize', query_string=params)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:400])
        fields = self._fields(response.get_data(as_text=True))
        response = self.client.post('/oauth/authorize', data={
            **{key: value for key, value in fields.items() if key != 'csrf_token'},
            'csrf_token': fields['csrf_token'], 'decision': 'approve'})
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True)[:400])
        query = parse_qs(urlparse(response.headers['Location']).query)
        return query['code'][0], verifier

    def tokens(self, client_id, redirect_uri, scope='alienxfile:read alienxfile:write'):
        code, verifier = self.authorization_code(client_id, redirect_uri, scope, 's')
        response = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': redirect_uri, 'client_id': client_id,
            'code_verifier': verifier, 'resource': AUDIENCE})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def rpc(self, tool, arguments, token):
        response = self.client.post(
            '/mcp', headers={'Authorization': 'Bearer ' + token},
            json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                  'params': {'name': tool, 'arguments': arguments}})
        return response, response.get_json(silent=True)

    def test_two_clients_receive_independent_tokens_and_families(self):
        alpha = self.register('Alpha Client', REDIRECT_A)
        beta = self.register('Beta Client', REDIRECT_B)
        alpha_tokens = self.tokens(alpha, REDIRECT_A)
        beta_tokens = self.tokens(beta, REDIRECT_B)
        self.assertNotEqual(alpha_tokens['access_token'], beta_tokens['access_token'])
        with app.app_context():
            self.assertEqual(validate_access_token(alpha_tokens['access_token'], AUDIENCE)['client_id'], alpha)
            self.assertEqual(validate_access_token(beta_tokens['access_token'], AUDIENCE)['client_id'], beta)
        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': alpha_tokens['refresh_token'],
            'client_id': alpha})
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            self.assertIsNotNone(validate_access_token(beta_tokens['access_token'], AUDIENCE))

    def test_code_cannot_be_exchanged_by_another_client(self):
        alpha = self.register('Alpha Client', REDIRECT_A)
        beta = self.register('Beta Client', REDIRECT_B)
        code, verifier = self.authorization_code(alpha, REDIRECT_A, 'alienxfile:read', 'a')
        response = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': REDIRECT_A, 'client_id': beta,
            'code_verifier': verifier, 'resource': AUDIENCE})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'invalid_grant')

    def test_refresh_token_is_bound_to_its_client(self):
        alpha = self.register('Alpha Client', REDIRECT_A)
        beta = self.register('Beta Client', REDIRECT_B)
        alpha_tokens = self.tokens(alpha, REDIRECT_A)
        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': alpha_tokens['refresh_token'],
            'client_id': beta})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'invalid_grant')
        with app.app_context():
            self.assertIsNotNone(validate_access_token(alpha_tokens['access_token'], AUDIENCE))

    def test_revoking_one_client_leaves_the_other_active(self):
        alpha = self.register('Alpha Client', REDIRECT_A)
        beta = self.register('Beta Client', REDIRECT_B)
        alpha_tokens = self.tokens(alpha, REDIRECT_A)
        beta_tokens = self.tokens(beta, REDIRECT_B)
        self.login()
        page = self._fields(self.client.get('/account').get_data(as_text=True))
        response = self.client.post('/account/revoke-client',
                                    data={'csrf_token': page['csrf_token'], 'client_id': alpha})
        self.assertEqual(response.status_code, 303)
        with app.app_context():
            self.assertIsNone(validate_access_token(alpha_tokens['access_token'], AUDIENCE))
            self.assertIsNotNone(validate_access_token(beta_tokens['access_token'], AUDIENCE))
        self.assertIn('Beta Client', self.client.get('/account').get_data(as_text=True))
        self.assertNotIn('Alpha Client', self.client.get('/account').get_data(as_text=True))

    def test_scopes_are_enforced_per_client(self):
        read_client = self.register('Read Client', REDIRECT_A, 'alienxfile:read')
        write_client = self.register('Write Client', REDIRECT_B, 'alienxfile:write')
        read_tokens = self.tokens(read_client, REDIRECT_A, 'alienxfile:read')
        write_tokens = self.tokens(write_client, REDIRECT_B, 'alienxfile:write')
        denied, body = self.rpc('share_text', {'text': 'read client cannot write'},
                                read_tokens['access_token'])
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(body['error']['code'], -32001)
        allowed, body = self.rpc('share_text', {'text': 'write client can write'},
                                 write_tokens['access_token'])
        self.assertEqual(allowed.status_code, 200)
        self.assertFalse(body['result']['isError'])
        denied, body = self.rpc('check_share', {'code': '12345'},
                                write_tokens['access_token'])
        self.assertEqual(denied.status_code, 403)

    def test_scope_escalation_during_authorization_is_rejected(self):
        alpha = self.register('Alpha Client', REDIRECT_A, 'alienxfile:read')
        response = self.client.get('/oauth/authorize', query_string={
            'client_id': alpha, 'redirect_uri': REDIRECT_A, 'response_type': 'code',
            'code_challenge': pkce_challenge('q' * 43), 'code_challenge_method': 'S256',
            'scope': 'alienxfile:read alienxfile:write', 'state': 'bad'})
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response.headers['Location']).query)
        self.assertEqual(query['error'][0], 'invalid_scope')

    def test_account_lists_both_consents(self):
        alpha = self.register('Alpha Client', REDIRECT_A)
        beta = self.register('Beta Client', REDIRECT_B)
        self.tokens(alpha, REDIRECT_A)
        self.tokens(beta, REDIRECT_B)
        self.login()
        page = self.client.get('/account').get_data(as_text=True)
        self.assertIn('Alpha Client', page)
        self.assertIn('Beta Client', page)
        self.assertEqual(page.count('Revoke access'), 2)

    def test_client_secret_is_not_shared_between_clients(self):
        alpha = self.client.post('/oauth/register', json={
            'client_name': 'Alpha Secret',
            'redirect_uris': [REDIRECT_A],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'client_secret_basic',
            'scope': 'alienxfile:read',
        }).get_json()
        beta = self.client.post('/oauth/register', json={
            'client_name': 'Beta Secret',
            'redirect_uris': [REDIRECT_B],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'client_secret_basic',
            'scope': 'alienxfile:read',
        }).get_json()
        self.assertNotEqual(alpha['client_secret'], beta['client_secret'])
        alpha_basic = base64.b64encode(
            f"{alpha['client_id']}:{alpha['client_secret']}".encode()).decode()
        response = self.client.post('/oauth/token', data={'grant_type': 'refresh_token'},
                                    headers={'Authorization': 'Basic ' + alpha_basic})
        self.assertEqual(response.status_code, 400)
        beta_basic = base64.b64encode(
            f"{alpha['client_id']}:{beta['client_secret']}".encode()).decode()
        response = self.client.post('/oauth/token', data={'grant_type': 'refresh_token'},
                                    headers={'Authorization': 'Basic ' + beta_basic})
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
