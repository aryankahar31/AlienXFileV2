import base64
import html as html_lib
import json
import re
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

from flask_app import app, get_db
from oauth.security import hash_password, pkce_challenge
from oauth.store import get_access_token, get_refresh_token, validate_access_token

OWNER = 'owner'
OWNER_PASSWORD = 'correct-horse-battery-staple'
OWNER_HASH = hash_password(OWNER_PASSWORD)
REDIRECT = 'https://client.example/callback'
AUDIENCE = 'https://example.test/mcp'
ISSUER = 'https://example.test'
SCOPES = 'alienxfile:read alienxfile:write'


class FakeCimdResponse:
    def __init__(self, document, status=200):
        self.status_code = status
        self.headers = {}
        self._body = json.dumps(document).encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, chunk_size=8192):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start:start + chunk_size]


class OAuthTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='alienx-oauth-test-')
        self.addCleanup(directory.cleanup)
        self.database = str(Path(directory.name) / 'oauth.sqlite3')
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(app.config, **{
            'TESTING': True,
            'DATABASE': self.database,
            'DATABASE_URL': None,
            'SECRET_KEY': 'oauth-test-secret-key',
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

    # ── helpers ─────────────────────────────────────────────────────────────

    def rpc(self, method, params=None, headers=None, request_id=1):
        body = {'jsonrpc': '2.0', 'id': request_id, 'method': method}
        if params is not None:
            body['params'] = params
        response = self.client.post('/mcp', json=body, headers=headers or {})
        return response, response.get_json(silent=True)

    def register(self, **overrides):
        body = {
            'client_name': 'Test Client',
            'redirect_uris': [REDIRECT],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
            'scope': SCOPES,
        }
        body.update(overrides)
        response = self.client.post('/oauth/register', json=body)
        return response, response.get_json(silent=True)

    @staticmethod
    def _fields(page):
        return {name: html_lib.unescape(value) for name, value in
                re.findall(r'name="([^"]+)" value="([^"]*)"', page)}

    def login(self, next_url='/account', password=OWNER_PASSWORD):
        page = self.client.get('/login', query_string={'next': next_url})
        if page.status_code == 303:
            return page
        self.assertEqual(page.status_code, 200)
        fields = self._fields(page.get_data(as_text=True))
        response = self.client.post('/login', data={
            'csrf_token': fields['csrf_token'],
            'next': fields['next'],
            'username': OWNER,
            'password': password,
        })
        return response

    def authorize(self, client_id, *, verifier=None, scope=SCOPES, state='state-1',
                  resource=AUDIENCE, login=True, decision='approve'):
        verifier = verifier or base64.urlsafe_b64encode(b'v' * 32).rstrip(b'=').decode()
        params = {
            'client_id': client_id,
            'redirect_uri': REDIRECT,
            'response_type': 'code',
            'code_challenge': pkce_challenge(verifier),
            'code_challenge_method': 'S256',
            'scope': scope,
            'state': state,
            'resource': resource,
        }
        response = self.client.get('/oauth/authorize', query_string=params)
        if login and response.status_code == 303 and response.headers['Location'].startswith('/login'):
            location = response.headers['Location']
            next_value = parse_qs(urlparse(location).query).get('next', ['/account'])[0]
            login_response = self.login(next_value)
            self.assertEqual(login_response.status_code, 303)
            response = self.client.get(login_response.headers['Location'])
        return response, params, verifier

    def approve(self, client_id, **kwargs):
        decision = kwargs.pop('decision', 'approve')
        response, params, verifier = self.authorize(client_id, **kwargs)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:500])
        page = response.get_data(as_text=True)
        self.assertIn('Authorize Test Client', page)
        fields = self._fields(page)
        return self.client.post('/oauth/authorize', data={
            **{key: value for key, value in fields.items() if key != 'csrf_token'},
            'csrf_token': fields['csrf_token'],
            'decision': decision,
        }), params, verifier

    def code_for(self, client_id, **kwargs):
        response, params, verifier = self.approve(client_id, **kwargs)
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True)[:500])
        query = parse_qs(urlparse(response.headers['Location']).query)
        return query['code'][0], params, verifier

    def token_for(self, client_id, **kwargs):
        code, params, verifier = self.code_for(client_id, **kwargs)
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

    # ── discovery ───────────────────────────────────────────────────────────

    def test_authorization_server_metadata(self):
        response = self.client.get('/.well-known/oauth-authorization-server')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Access-Control-Allow-Origin'], '*')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        data = response.get_json()
        self.assertEqual(data['issuer'], ISSUER)
        self.assertEqual(data['authorization_endpoint'], ISSUER + '/oauth/authorize')
        self.assertEqual(data['token_endpoint'], ISSUER + '/oauth/token')
        self.assertEqual(data['registration_endpoint'], ISSUER + '/oauth/register')
        self.assertEqual(data['code_challenge_methods_supported'], ['S256'])
        self.assertEqual(set(data['scopes_supported']),
                         {'alienxfile:read', 'alienxfile:write',
                          'alienxfile:delete', 'alienxfile:admin'})

    def test_protected_resource_metadata_on_both_paths(self):
        for path in ('/.well-known/oauth-protected-resource',
                     '/.well-known/oauth-protected-resource/mcp'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['resource'], AUDIENCE)
            self.assertEqual(response.get_json()['authorization_servers'], [ISSUER])

    def test_discovery_is_404_when_oauth_disabled(self):
        with patch.dict(app.config, OAUTH_ENABLED=False):
            for path in ('/.well-known/oauth-authorization-server',
                         '/.well-known/oauth-protected-resource'):
                self.assertEqual(self.client.get(path).status_code, 404)

    # ── dynamic client registration ─────────────────────────────────────────

    def test_dynamic_registration_public_client(self):
        response, data = self.register()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertTrue(data['client_id'].startswith('axclient_'))
        self.assertNotIn('client_secret', data)
        self.assertEqual(data['redirect_uris'], [REDIRECT])
        self.assertEqual(data['scope'], SCOPES)

    def test_dynamic_registration_confidential_client_and_basic_auth(self):
        response, data = self.register(token_endpoint_auth_method='client_secret_basic')
        self.assertEqual(response.status_code, 201)
        secret = data['client_secret']
        self.assertTrue(secret.startswith('axsecret_'))
        basic = base64.b64encode(f"{data['client_id']}:{secret}".encode()).decode()
        response = self.client.post('/oauth/token', data={'grant_type': 'refresh_token',
                                                          'refresh_token': 'nope'},
                                    headers={'Authorization': 'Basic ' + basic})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'invalid_grant')
        with app.app_context():
            row = get_db().execute('SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?',
                                   (data['client_id'],)).fetchone()
        self.assertNotEqual(row['client_secret_hash'], secret)
        self.assertNotIn(secret, row['client_secret_hash'])

    def test_registration_rejects_invalid_metadata(self):
        cases = [
            ({'redirect_uris': ['http://evil.example/cb']}, 'redirect_uris'),
            ({'response_types': ['token']}, 'response_types'),
            ({'grant_types': ['client_credentials']}, 'grant_types'),
            ({'scope': 'alienxfile:unknown'}, 'Unsupported scope'),
            ({'token_endpoint_auth_method': 'private_key_jwt'}, 'auth_method'),
        ]
        for override, text in cases:
            response, data = self.register(**override)
            self.assertEqual(response.status_code, 400, override)
            self.assertEqual(data['error'], 'invalid_client_metadata')
            self.assertIn(text, data['error_description'])

    def test_authorization_defaults_to_registered_scope_when_omitted(self):
        response = self.client.post('/oauth/register', json={
            'client_name': 'Read-only Client',
            'redirect_uris': [REDIRECT],
            'scope': 'alienxfile:read',
        })
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        client_id = response.get_json()['client_id']
        challenge = pkce_challenge('a' * 43)
        self.assertEqual(self.login().status_code, 303)
        params = {
            'client_id': client_id, 'redirect_uri': REDIRECT, 'response_type': 'code',
            'code_challenge': challenge, 'code_challenge_method': 'S256',
            'resource': AUDIENCE,
        }
        page = self.client.get('/oauth/authorize?' + urlencode(params))
        self.assertEqual(page.status_code, 200, page.get_data(as_text=True))
        text = page.get_data(as_text=True)
        self.assertIn('name="scope" value="alienxfile:read"', text)
        self.assertIn('Read shares and check share status', text)

    def test_registration_defaults_to_read_and_write(self):
        response = self.client.post('/oauth/register', json={
            'client_name': 'Default Scope Client',
            'redirect_uris': [REDIRECT],
            'response_types': ['code'],
        })
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertEqual(response.get_json()['scope'], SCOPES)

    def test_registration_can_be_disabled(self):
        with patch.dict(app.config, OAUTH_DCR_ENABLED=False):
            response, data = self.register()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(data['error'], 'invalid_client_metadata')

    def test_unknown_and_malformed_client_auth(self):
        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'client_id': 'missing', 'refresh_token': 'x'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()['error'], 'invalid_client')
        response = self.client.post('/oauth/token', data={'grant_type': 'refresh_token'},
                                    headers={'Authorization': 'Basic !!!'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('Basic', response.headers['WWW-Authenticate'])
        _, data = self.register()
        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'client_id': data['client_id'],
            'client_secret': 'wrong', 'refresh_token': 'x'})
        self.assertEqual(response.status_code, 401)

    # ── authorization endpoint ──────────────────────────────────────────────

    def test_authorize_rejects_unknown_client_and_redirect(self):
        self.assertEqual(self.client.get('/oauth/authorize?client_id=missing').status_code, 400)
        _, data = self.register()
        response = self.client.get('/oauth/authorize', query_string={
            'client_id': data['client_id'], 'redirect_uri': 'https://evil.example/cb',
            'response_type': 'code'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('not registered', response.get_data(as_text=True))

    def test_authorize_redirects_protocol_errors_to_client(self):
        _, data = self.register()
        cases = [
            ({'response_type': 'token'}, 'unsupported_response_type'),
            ({'code_challenge': ''}, 'invalid_request'),
            ({'code_challenge_method': 'plain'}, 'invalid_request'),
            ({'resource': 'https://other.example/mcp'}, 'invalid_target'),
            ({'scope': 'alienxfile:unknown'}, 'invalid_scope'),
        ]
        for override, expected in cases:
            params = {
                'client_id': data['client_id'], 'redirect_uri': REDIRECT,
                'response_type': 'code',
                'code_challenge': pkce_challenge('a' * 43),
                'code_challenge_method': 'S256', 'state': 'abc',
            }
            params.update(override)
            response = self.client.get('/oauth/authorize', query_string=params)
            self.assertEqual(response.status_code, 302, override)
            query = parse_qs(urlparse(response.headers['Location']).query)
            self.assertEqual(query['error'][0], expected, override)
            self.assertEqual(query['state'][0], 'abc')
            self.assertEqual(query['iss'][0], ISSUER)

    def test_authorize_requires_login_and_renders_consent_without_secrets(self):
        _, data = self.register()
        response, _, _ = self.authorize(data['client_id'], login=False)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers['Location'].startswith('/login?next='))
        response, _, _ = self.authorize(data['client_id'])
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Authorize Test Client', page)
        self.assertIn('alienxfile:read', page)
        self.assertIn(REDIRECT, page)
        self.assertNotIn(OWNER_HASH, page)
        self.assertNotIn('client_secret', page)
        self.assertNotIn('code=', page)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_login_rejects_bad_password_and_bad_csrf(self):
        response = self.login(password='wrong-password')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Invalid username or password', response.get_data(as_text=True))
        response = self.client.post('/login', data={'username': OWNER, 'password': OWNER_PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertIn('expired', response.get_data(as_text=True))

    def test_login_cookie_flags_and_logout(self):
        response = self.login()
        self.assertEqual(response.status_code, 303)
        cookies = response.headers.getlist('Set-Cookie')
        session_cookie = next(value for value in cookies if value.startswith('alienx_owner_session='))
        self.assertIn('HttpOnly', session_cookie)
        self.assertIn('SameSite=Lax', session_cookie)
        self.assertNotIn('Secure', session_cookie)
        page = self.client.get('/account')
        self.assertEqual(page.status_code, 200)
        fields = self._fields(page.get_data(as_text=True))
        response = self.client.post('/logout', data={'csrf_token': fields['csrf_token']})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.get('/account').status_code, 303)

    def test_consent_denial_returns_access_denied(self):
        _, data = self.register()
        response, _, _ = self.approve(data['client_id'], decision='deny')
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response.headers['Location']).query)
        self.assertEqual(query['error'][0], 'access_denied')
        self.assertEqual(query['state'][0], 'state-1')

    def test_consent_rejects_wrong_csrf(self):
        _, data = self.register()
        response, _, _ = self.authorize(data['client_id'])
        fields = self._fields(response.get_data(as_text=True))
        response = self.client.post('/oauth/authorize', data={
            **{key: value for key, value in fields.items() if key != 'csrf_token'},
            'csrf_token': 'forged', 'decision': 'approve'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('expired', response.get_data(as_text=True))

    def test_approved_code_is_hashed_state_and_iss_are_returned(self):
        _, data = self.register()
        code, params, _ = self.code_for(data['client_id'])
        self.assertTrue(len(code) >= 40)
        self.assertEqual(params['state'], 'state-1')
        with app.app_context():
            row = get_db().execute('SELECT code_hash FROM oauth_authorization_codes').fetchone()
            self.assertNotEqual(row['code_hash'], code)

    # ── token endpoint ──────────────────────────────────────────────────────

    def test_authorization_code_exchange_returns_bearer_tokens(self):
        _, data = self.register()
        code, _, verifier = self.code_for(data['client_id'])
        response = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT,
            'client_id': data['client_id'],
            'code_verifier': verifier,
            'resource': AUDIENCE,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        body = response.get_json()
        self.assertEqual(body['token_type'], 'Bearer')
        self.assertEqual(body['scope'], SCOPES)
        self.assertEqual(body['resource'], AUDIENCE)
        self.assertGreater(body['expires_in'], 0)
        self.assertIn('refresh_token', body)
        with app.app_context():
            row = get_access_token(body['access_token'])
            self.assertIsNotNone(row)
            self.assertNotEqual(row['token_hash'], body['access_token'])
            context = validate_access_token(body['access_token'], AUDIENCE)
            self.assertEqual(context['owner'], OWNER)
            self.assertIsNone(validate_access_token(body['access_token'], 'https://other/mcp'))

    def test_token_rejects_wrong_pkce_redirect_and_resource(self):
        _, data = self.register()
        code, _, verifier = self.code_for(data['client_id'])
        for override, expected in [
            ({'code_verifier': 'b' * 43}, 'invalid_grant'),
            ({'redirect_uri': 'https://client.example/other'}, 'invalid_grant'),
            ({'resource': 'https://other.example/mcp'}, 'invalid_target'),
        ]:
            body = {
                'grant_type': 'authorization_code', 'code': code,
                'redirect_uri': REDIRECT, 'client_id': data['client_id'],
                'code_verifier': verifier, 'resource': AUDIENCE,
            }
            body.update(override)
            response = self.client.post('/oauth/token', data=body)
            self.assertEqual(response.status_code, 400, override)
            self.assertEqual(response.get_json()['error'], expected)
        response = self.client.post('/oauth/token', json={'grant_type': 'authorization_code'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'invalid_request')

    def test_code_replay_revokes_issued_family(self):
        _, data = self.register()
        code, _, verifier = self.code_for(data['client_id'])
        exchange = {
            'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': REDIRECT, 'client_id': data['client_id'],
            'code_verifier': verifier, 'resource': AUDIENCE,
        }
        response = self.client.post('/oauth/token', data=exchange)
        self.assertEqual(response.status_code, 200)
        tokens = response.get_json()
        with app.app_context():
            self.assertIsNotNone(validate_access_token(tokens['access_token'], AUDIENCE))
        replay = self.client.post('/oauth/token', data=exchange)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.get_json()['error'], 'invalid_grant')
        with app.app_context():
            self.assertIsNone(validate_access_token(tokens['access_token'], AUDIENCE))
        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
            'client_id': data['client_id']})
        self.assertEqual(response.status_code, 400)

    def test_expired_authorization_code_is_rejected(self):
        _, data = self.register()
        code, _, verifier = self.code_for(data['client_id'])
        with patch('oauth.blueprint.time.time', return_value=time.time() + 10_000), \
                patch('oauth.store.time.time', return_value=time.time() + 10_000):
            response = self.client.post('/oauth/token', data={
                'grant_type': 'authorization_code', 'code': code,
                'redirect_uri': REDIRECT, 'client_id': data['client_id'],
                'code_verifier': verifier, 'resource': AUDIENCE})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'invalid_grant')

    def test_refresh_rotation_replay_and_scope_narrowing(self):
        _, data = self.register()
        tokens = self.token_for(data['client_id'])
        response = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
            'client_id': data['client_id'], 'scope': 'alienxfile:read'})
        self.assertEqual(response.status_code, 200)
        rotated = response.get_json()
        self.assertEqual(rotated['scope'], 'alienxfile:read')
        self.assertNotEqual(rotated['refresh_token'], tokens['refresh_token'])
        replay = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
            'client_id': data['client_id']})
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.get_json()['error'], 'invalid_grant')
        revoked = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': rotated['refresh_token'],
            'client_id': data['client_id']})
        self.assertEqual(revoked.status_code, 400)
        escalation = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': rotated['refresh_token'],
            'client_id': data['client_id'], 'scope': 'alienxfile:read alienxfile:admin'})
        self.assertEqual(escalation.status_code, 400)

    def test_revocation_is_idempotent_and_family_wide(self):
        _, data = self.register()
        tokens = self.token_for(data['client_id'])
        response = self.client.post('/oauth/revoke', data={
            'token': tokens['access_token'], 'client_id': data['client_id']})
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            self.assertIsNone(validate_access_token(tokens['access_token'], AUDIENCE))
            self.assertIsNotNone(get_refresh_token(tokens['refresh_token'])['revoked_at'])
        response = self.client.post('/oauth/revoke', data={
            'token': 'unknown-token', 'client_id': data['client_id']})
        self.assertEqual(response.status_code, 200)

    def test_token_rate_limit_returns_retry_after(self):
        with patch.dict(app.config, OAUTH_TOKEN_RATE_LIMIT=1):
            first = self.client.post('/oauth/token', data={'grant_type': 'refresh_token'})
            second = self.client.post('/oauth/token', data={'grant_type': 'refresh_token'})
        self.assertNotEqual(first.status_code, 429)
        self.assertEqual(second.status_code, 429)
        self.assertIn('Retry-After', second.headers)

    # ── MCP scopes ──────────────────────────────────────────────────────────

    def test_mcp_requires_oauth_and_advertises_challenge(self):
        response, body = self.rpc('tools/list')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body['error']['code'], -32001)
        challenge = response.headers['WWW-Authenticate']
        self.assertTrue(challenge.startswith('Bearer '))
        self.assertIn('resource_metadata="' + ISSUER +
                      '/.well-known/oauth-protected-resource"', challenge)
        response, body = self.rpc('tools/list', headers={'Authorization': 'Bearer invalid'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('invalid_token', response.headers['WWW-Authenticate'])

    def test_mcp_read_and_write_scopes_are_enforced(self):
        _, data = self.register(scope='alienxfile:read alienxfile:write alienxfile:admin')
        read_only = self.token_for(data['client_id'], scope='alienxfile:read')
        write_only = self.token_for(data['client_id'], scope='alienxfile:write')
        admin = self.token_for(data['client_id'], scope='alienxfile:admin')
        response, _ = self.rpc('tools/list',
                               headers={'Authorization': 'Bearer ' + read_only['access_token']})
        self.assertEqual(response.status_code, 200)
        response, body = self.rpc(
            'tools/call', {'name': 'share_text', 'arguments': {'text': 'blocked'}},
            headers={'Authorization': 'Bearer ' + read_only['access_token']})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(body['error']['code'], -32001)
        self.assertIn('insufficient_scope', response.headers['WWW-Authenticate'])
        self.assertIn('alienxfile:write', response.headers['WWW-Authenticate'])
        response, body = self.rpc(
            'tools/call', {'name': 'share_text', 'arguments': {'text': 'allowed'}},
            headers={'Authorization': 'Bearer ' + write_only['access_token']})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(body['result']['isError'])
        response, body = self.rpc(
            'tools/call', {'name': 'share_text', 'arguments': {'text': 'admin'}},
            headers={'Authorization': 'Bearer ' + admin['access_token']})
        self.assertEqual(response.status_code, 200)

    def test_mcp_tool_catalog_declares_oauth_flow(self):
        response, body = self.rpc('tools/list',
                                  headers={'Authorization': 'Bearer ' + self._admin_token()})
        tools = body['result']['tools']
        for tool in tools:
            oauth = tool['securitySchemes']['oauth2']
            self.assertEqual(oauth['flows']['authorizationCode']['authorizationUrl'],
                             ISSUER + '/oauth/authorize')
            self.assertEqual(oauth['flows']['authorizationCode']['tokenUrl'],
                             ISSUER + '/oauth/token')

    def test_api_key_still_works_as_owner_fallback(self):
        with patch.dict(app.config, MCP_API_KEY='owner-api-key'):
            denied, _ = self.rpc('tools/list')
            self.assertEqual(denied.status_code, 401)
            response, body = self.rpc('tools/list', headers={
                'Authorization': 'Bearer owner-api-key'})
            self.assertEqual(response.status_code, 200)
            self.assertIn('tools', body['result'])

    def test_mcp_oauth_can_be_disabled_for_static_key_mode(self):
        _, data = self.register(scope='alienxfile:admin')
        token = self.token_for(data['client_id'], scope='alienxfile:admin')['access_token']
        with patch.dict(app.config, MCP_OAUTH_ENABLED=False, MCP_API_KEY='static-key'):
            denied, body = self.rpc('tools/list', headers={'Authorization': 'Bearer ' + token})
            self.assertEqual(denied.status_code, 401)
            self.assertEqual(body['error']['code'], -32001)
            response, body = self.rpc('tools/list', headers={
                'Authorization': 'Bearer static-key'})
            self.assertEqual(response.status_code, 200)
            self.assertIn('tools', body['result'])

    def _admin_token(self):
        _, data = self.register(scope='alienxfile:admin')
        return self.token_for(data['client_id'], scope='alienxfile:admin')['access_token']

    # ── account ─────────────────────────────────────────────────────────────

    def test_account_lists_and_revokes_clients(self):
        _, data = self.register()
        tokens = self.token_for(data['client_id'])
        self.login()
        page = self.client.get('/account').get_data(as_text=True)
        self.assertIn('Test Client', page)
        self.assertIn(data['client_id'], page)
        fields = self._fields(page)
        response = self.client.post(
            '/account/revoke-client',
            data={'csrf_token': fields['csrf_token'], 'client_id': data['client_id']})
        self.assertEqual(response.status_code, 303)
        with app.app_context():
            self.assertIsNone(validate_access_token(tokens['access_token'], AUDIENCE))
        page = self.client.get('/account').get_data(as_text=True)
        self.assertIn('No connected applications', page)

    def test_account_revoke_rejects_wrong_csrf(self):
        _, data = self.register()
        self.token_for(data['client_id'])
        self.login()
        response = self.client.post('/account/revoke-client',
                                    data={'csrf_token': 'forged', 'client_id': data['client_id']})
        self.assertEqual(response.status_code, 400)

    # ── CIMD and redirect hardening ─────────────────────────────────────────

    def test_client_id_metadata_document_is_resolved_and_cached(self):
        client_id = 'https://client.example/oauth-client.json'
        document = {
            'client_id': client_id,
            'client_name': 'Metadata Client',
            'redirect_uris': [REDIRECT],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': SCOPES,
        }
        with patch('flask_app._is_private_host', return_value=False), \
                patch('oauth.blueprint.requests.get',
                      return_value=FakeCimdResponse(document)) as fetched:
            response, _, _ = self.authorize(client_id, login=False)
            self.assertEqual(response.status_code, 303)
            self.assertEqual(fetched.call_count, 1)
        with app.app_context():
            row = get_db().execute('SELECT source, client_name FROM oauth_clients WHERE client_id = ?',
                                   (client_id,)).fetchone()
        self.assertEqual(row['source'], 'cimd')
        self.assertEqual(row['client_name'], 'Metadata Client')

    def test_client_id_metadata_document_rejects_mismatch_and_private_host(self):
        client_id = 'https://client.example/oauth-client.json'
        document = {'client_id': 'https://client.example/other.json',
                    'client_name': 'Bad', 'redirect_uris': [REDIRECT]}
        with patch('flask_app._is_private_host', return_value=False), \
                patch('oauth.blueprint.requests.get',
                      return_value=FakeCimdResponse(document)):
            response, _, _ = self.authorize(client_id, login=False)
        self.assertEqual(response.status_code, 400)
        with patch('flask_app._is_private_host', return_value=True):
            response, _, _ = self.authorize(client_id, login=False)
        self.assertEqual(response.status_code, 400)

    def test_login_next_rejects_absolute_and_backslash_redirects(self):
        for target in ('https://evil.example', '//evil.example', '/\\evil.example',
                       '/%2f%2fevil.example', '/%5cevil.example'):
            page = self.client.get('/login', query_string={'next': target})
            fields = self._fields(page.get_data(as_text=True))
            self.assertEqual(fields['next'], '/account')

    def test_responses_never_leak_owner_secrets(self):
        _, data = self.register()
        tokens = self.token_for(data['client_id'])
        self.login()
        pages = [
            self.client.get('/account').get_data(as_text=True),
            self.client.get('/oauth/authorize', query_string={
                'client_id': data['client_id'], 'redirect_uri': REDIRECT,
                'response_type': 'code',
                'code_challenge': pkce_challenge('z' * 43),
                'code_challenge_method': 'S256'}).get_data(as_text=True),
            json.dumps(tokens),
        ]
        for text in pages:
            self.assertNotIn(OWNER_HASH, text)
            self.assertNotIn('client_secret_hash', text)
            self.assertNotIn('token_hash', text)


if __name__ == '__main__':
    unittest.main()
