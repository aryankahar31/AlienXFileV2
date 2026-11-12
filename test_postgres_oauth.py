"""PostgreSQL-only end-to-end OAuth browser flow test."""
import base64
import html as html_lib
import os
import re
import unittest
import uuid
from contextlib import ExitStack
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

TEST_URL = os.environ.get('ALIENX_TEST_DATABASE_URL')
if TEST_URL:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from flask_app import app, get_db
    from oauth.security import hash_password, pkce_challenge
    from oauth.store import get_refresh_token, validate_access_token

OWNER = 'owner'
OWNER_PASSWORD = 'correct-horse-battery-staple'
REDIRECT = 'https://client.example/callback'
ISSUER = 'https://example.test'
AUDIENCE = ISSUER + '/mcp'
SCOPES = 'alienxfile:read alienxfile:write'


@unittest.skipUnless(TEST_URL, 'Set ALIENX_TEST_DATABASE_URL to run isolated PostgreSQL tests')
class PostgresOAuthFlowTest(unittest.TestCase):
    def setUp(self):
        schema = 'alienx_oauth_test_' + uuid.uuid4().hex
        self.dsn = make_conninfo(TEST_URL, options=f'-c search_path={schema}')
        admin = psycopg.connect(self.dsn, autocommit=True, connect_timeout=10)
        self.addCleanup(admin.close)
        admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        self.addCleanup(admin.execute, sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(patch.dict(app.config, **{
            'TESTING': True,
            'DATABASE': ':memory:',
            'DATABASE_URL': self.dsn,
            'BLOB_READ_WRITE_TOKEN': '',
            'SECRET_KEY': 'postgres-oauth-test-secret-key',
            'OAUTH_ENABLED': True,
            'OAUTH_ISSUER': ISSUER,
            'OAUTH_AUDIENCE': AUDIENCE,
            'OAUTH_OWNER_CONFIGURED': True,
            'OWNER_USERNAME': OWNER,
            'OWNER_PASSWORD_HASH': hash_password(OWNER_PASSWORD),
            'OAUTH_ACCESS_TOKEN_TTL': 900,
            'OAUTH_REFRESH_TOKEN_TTL': 2592000,
            'OAUTH_CODE_TTL': 300,
            'OAUTH_SESSION_TTL': 43200,
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
            'TRUST_PYTHONANYWHERE_PROXY': False,
            'TRUST_RENDER_PROXY': False,
        }))
        contexts.enter_context(patch(
            'requests.sessions.Session.request',
            side_effect=AssertionError('Unexpected outbound request')))
        result = app.test_cli_runner().invoke(args=['init-db'])
        self.assertEqual(result.exit_code, 0, 'init-db failed in isolated PostgreSQL schema')
        with app.app_context():
            self.assertIsInstance(get_db(), psycopg.Connection)
            table = get_db().execute(
                "SELECT to_regclass('oauth_clients') AS name").fetchone()['name']
            self.assertEqual(table, 'oauth_clients')
        self.client = app.test_client()

    @staticmethod
    def _fields(page):
        return {name: html_lib.unescape(value) for name, value in
                re.findall(r'name="([^"]+)" value="([^"]*)"', page)}

    def register(self):
        response = self.client.post('/oauth/register', json={
            'client_name': 'PostgreSQL Client',
            'redirect_uris': [REDIRECT],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
            'scope': SCOPES,
        })
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()['client_id']

    def login_and_authorize(self, client_id, verifier):
        params = {
            'client_id': client_id,
            'redirect_uri': REDIRECT,
            'response_type': 'code',
            'code_challenge': pkce_challenge(verifier),
            'code_challenge_method': 'S256',
            'scope': SCOPES,
            'state': 'postgres-state',
            'resource': AUDIENCE,
        }
        response = self.client.get('/oauth/authorize', query_string=params)
        if response.status_code == 303:
            self.assertTrue(response.headers['Location'].startswith('/login?next='))
            login_target = parse_qs(urlparse(response.headers['Location']).query)['next'][0]
            page = self.client.get('/login', query_string={'next': login_target})
            self.assertEqual(page.status_code, 200)
            fields = self._fields(page.get_data(as_text=True))
            response = self.client.post('/login', data={
                'csrf_token': fields['csrf_token'],
                'next': fields['next'],
                'username': OWNER,
                'password': OWNER_PASSWORD,
            })
            self.assertEqual(response.status_code, 303)
            page = self.client.get(response.headers['Location'])
        else:
            page = response
        self.assertEqual(page.status_code, 200, page.get_data(as_text=True)[:500])
        self.assertIn('Authorize PostgreSQL Client', page.get_data(as_text=True))
        fields = self._fields(page.get_data(as_text=True))
        response = self.client.post('/oauth/authorize', data={
            **{key: value for key, value in fields.items() if key != 'csrf_token'},
            'csrf_token': fields['csrf_token'],
            'decision': 'approve',
        })
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True)[:500])
        query = parse_qs(urlparse(response.headers['Location']).query)
        self.assertEqual(query['state'], ['postgres-state'])
        self.assertEqual(query['iss'], [ISSUER])
        return query['code'][0]

    def exchange_code(self, client_id, code, verifier):
        response = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT,
            'client_id': client_id,
            'code_verifier': verifier,
            'resource': AUDIENCE,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_browser_flow_refresh_rotation_and_revocation(self):
        client_id = self.register()
        verifier = base64.urlsafe_b64encode(b'p' * 32).rstrip(b'=').decode()
        tokens = self.exchange_code(client_id, self.login_and_authorize(client_id, verifier), verifier)
        with app.app_context():
            context = validate_access_token(tokens['access_token'], AUDIENCE)
            self.assertEqual(context['client_id'], client_id)
            self.assertEqual(context['owner'], OWNER)
            self.assertEqual(set(context['scopes']), {'alienxfile:read', 'alienxfile:write'})

        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token'],
            'client_id': client_id,
            'resource': AUDIENCE,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        rotated = response.get_json()
        self.assertNotEqual(rotated['refresh_token'], tokens['refresh_token'])

        replay = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token'],
            'client_id': client_id,
            'resource': AUDIENCE,
        })
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.get_json()['error'], 'invalid_grant')
        with app.app_context():
            self.assertIsNone(validate_access_token(rotated['access_token'], AUDIENCE))
            self.assertIsNotNone(get_refresh_token(rotated['refresh_token'])['revoked_at'])

        fresh_verifier = base64.urlsafe_b64encode(b'q' * 32).rstrip(b'=').decode()
        fresh = self.exchange_code(client_id, self.login_and_authorize(client_id, fresh_verifier),
                                   fresh_verifier)
        response = self.client.post('/oauth/revoke', data={
            'token': fresh['access_token'],
            'client_id': client_id,
        })
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            self.assertIsNone(validate_access_token(fresh['access_token'], AUDIENCE))
            self.assertIsNotNone(get_refresh_token(fresh['refresh_token'])['revoked_at'])


if __name__ == '__main__':
    unittest.main()
