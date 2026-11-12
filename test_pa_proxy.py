"""Tests for the hardened Litterbox proxy.

The proxy is deployed separately from the Flask app, so it is loaded here by
file path with an explicit environment. That also lets the tests prove that
the service refuses to start without a real secret.
"""
import importlib.util
import io
import os
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

PROXY_DIR = Path(__file__).resolve().parent / 'pa_proxy'
sys.path.insert(0, str(PROXY_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pa_proxy.tickets import issue_ticket, verify_ticket  # noqa: E402

VALID_SECRET = 'a' * 43
LITTERBOX_LINK = 'https://litter.catbox.moe/abc123XY'


def load_proxy(secret=VALID_SECRET, module_name='pa_proxy_under_test'):
    """Import pa_proxy/app.py with a controlled environment."""
    spec = importlib.util.spec_from_file_location(module_name, PROXY_DIR / 'app.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    stack = ExitStack()
    env = {'LITTERBOX_PROXY_SECRET': secret} if secret is not None else {}
    with patch.dict(os.environ, env, clear=False):
        if secret is None:
            os.environ.pop('LITTERBOX_PROXY_SECRET', None)
        spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, text=LITTERBOX_LINK):
        self.text = text


class FakeSession:
    def __init__(self, link=LITTERBOX_LINK):
        self.link = link
        self.calls = []

    def post(self, url, data=None, files=None, headers=None, timeout=None):
        self.calls.append({'url': url, 'data': data, 'files': files, 'headers': headers})
        return FakeResponse(self.link)


class ProxyStartupTest(unittest.TestCase):
    def test_missing_secret_refuses_to_start(self):
        with self.assertRaises(RuntimeError) as caught:
            load_proxy(secret=None, module_name='pa_proxy_no_secret')
        self.assertIn('LITTERBOX_PROXY_SECRET', str(caught.exception))

    def test_placeholder_secret_refuses_to_start(self):
        with self.assertRaises(RuntimeError):
            load_proxy(secret='CHANGE_ME_TO_A_RANDOM_SECRET', module_name='pa_proxy_placeholder')

    def test_short_secret_refuses_to_start(self):
        with self.assertRaises(RuntimeError):
            load_proxy(secret='short-secret', module_name='pa_proxy_short')

    def test_wsgi_module_has_no_fallback_secret(self):
        source = (PROXY_DIR / 'wsgi.py').read_text()
        self.assertNotIn('CHANGE_ME_TO_A_RANDOM_SECRET', source)
        self.assertNotIn('os.environ.setdefault', source)


class ProxyBehaviourTest(unittest.TestCase):
    def setUp(self):
        self.module = load_proxy(module_name='pa_proxy_behaviour')
        self.module.UPLOAD_LIMITER = self.module._FixedWindowLimiter(30, 3600)
        self.module.SERVER_LIMITER = self.module._FixedWindowLimiter(600, 3600)
        self.module.NONCES = self.module._NonceStore()
        self.client = self.module.app.test_client()
        self.session = FakeSession()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(self.module, 'create_session',
                                              return_value=self.session))

    def _upload(self, ticket=None, size=5, headers=None, data=None):
        payload = {'time': '1h'}
        if data is not None:
            payload = data
        else:
            payload['fileToUpload'] = (io.BytesIO(b'x' * size), 'note.txt')
        request_headers = dict(headers or {})
        if ticket is not None:
            request_headers['X-Upload-Ticket'] = ticket
        return self.client.post('/upload', data=payload, headers=request_headers,
                                 content_type='multipart/form-data')

    # ── server-to-server route ──────────────────────────────────────────────

    def test_proxy_upload_requires_the_shared_secret(self):
        response = self.client.post('/proxy/litterbox', data={
            'time': '1h', 'fileToUpload': (io.BytesIO(b'hello'), 'a.txt')},
            content_type='multipart/form-data')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.session.calls, [])

        response = self.client.post('/proxy/litterbox', data={
            'time': '1h', 'fileToUpload': (io.BytesIO(b'hello'), 'a.txt')},
            headers={'X-Proxy-Secret': 'wrong-secret-value'},
            content_type='multipart/form-data')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.session.calls, [])

    def test_proxy_upload_succeeds_with_the_shared_secret(self):
        response = self.client.post('/proxy/litterbox', data={
            'time': '1h', 'fileToUpload': (io.BytesIO(b'hello'), 'a.txt')},
            headers={'X-Proxy-Secret': VALID_SECRET},
            content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['url'], LITTERBOX_LINK)
        self.assertEqual(len(self.session.calls), 1)

    # ── browser route ───────────────────────────────────────────────────────

    def test_upload_without_a_ticket_is_refused(self):
        response = self._upload()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.session.calls, [])

    def test_upload_with_a_forged_ticket_is_refused(self):
        forged = issue_ticket('a-different-secret-value-000000000000000', size=5)
        response = self._upload(ticket=forged)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.session.calls, [])

    def test_upload_with_an_expired_ticket_is_refused(self):
        expired = issue_ticket(VALID_SECRET, size=5, expires_at=1_000_000_000)
        response = self._upload(ticket=expired)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.session.calls, [])

    def test_upload_with_a_valid_ticket_succeeds(self):
        ticket = issue_ticket(VALID_SECRET, size=5)
        response = self._upload(ticket=ticket, size=5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['url'], LITTERBOX_LINK)
        self.assertEqual(len(self.session.calls), 1)

    def test_ticket_cannot_be_replayed(self):
        ticket = issue_ticket(VALID_SECRET, size=5)
        first = self._upload(ticket=ticket, size=5)
        self.assertEqual(first.status_code, 200)
        second = self._upload(ticket=ticket, size=5)
        self.assertEqual(second.status_code, 403)
        self.assertEqual(len(self.session.calls), 1)

    def test_ticket_does_not_cover_a_larger_file(self):
        ticket = issue_ticket(VALID_SECRET, size=5)
        response = self._upload(ticket=ticket, size=4096)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.session.calls, [])

    def test_upload_is_rate_limited_per_client(self):
        self.module.UPLOAD_LIMITER = self.module._FixedWindowLimiter(2, 3600)
        headers = {'X-Forwarded-For': '203.0.113.10'}
        for _ in range(2):
            response = self._upload(ticket=issue_ticket(VALID_SECRET, size=5), size=5,
                                    headers=headers)
            self.assertEqual(response.status_code, 200)
        blocked = self._upload(ticket=issue_ticket(VALID_SECRET, size=5), size=5,
                               headers=headers)
        self.assertEqual(blocked.status_code, 429)
        self.assertIn('Retry-After', blocked.headers)

    def test_rate_limit_is_scoped_per_client(self):
        self.module.UPLOAD_LIMITER = self.module._FixedWindowLimiter(1, 3600)
        first = self._upload(ticket=issue_ticket(VALID_SECRET, size=5), size=5,
                             headers={'X-Forwarded-For': '203.0.113.11'})
        self.assertEqual(first.status_code, 200)
        other = self._upload(ticket=issue_ticket(VALID_SECRET, size=5), size=5,
                              headers={'X-Forwarded-For': '203.0.113.12'})
        self.assertEqual(other.status_code, 200)

    def test_cors_preflight_allows_the_ticket_header(self):
        response = self.client.options('/upload', headers={
            'Origin': 'https://alienxfilev2.onrender.com',
            'Access-Control-Request-Method': 'POST',
        })
        self.assertEqual(response.status_code, 204)
        self.assertIn('X-Upload-Ticket', response.headers['Access-Control-Allow-Headers'])
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                         'https://alienxfilev2.onrender.com')

    def test_credentials_are_never_logged(self):
        ticket = issue_ticket(VALID_SECRET, size=5)
        with self.assertLogs(self.module.app.logger, level='WARNING') as captured:
            response = self._upload(ticket='v1.1.deadbeef.5.forged')
        self.assertEqual(response.status_code, 403)
        logged = '\n'.join(captured.output)
        self.assertNotIn(VALID_SECRET, logged)
        self.assertNotIn(ticket, logged)
        self.assertNotIn('forged', logged)


class TicketTest(unittest.TestCase):
    def test_round_trip(self):
        ticket = issue_ticket(VALID_SECRET, size=1024)
        claims = verify_ticket(VALID_SECRET, ticket, max_size=2048)
        self.assertEqual(claims['size'], 1024)
        self.assertTrue(claims['nonce'])

    def test_tampered_ticket_is_rejected(self):
        ticket = issue_ticket(VALID_SECRET, size=1024)
        tampered = ticket[:-4] + ('aaaa' if not ticket.endswith('aaaa') else 'bbbb')
        with self.assertRaises(ValueError):
            verify_ticket(VALID_SECRET, tampered, max_size=2048)

    def test_ticket_signed_with_another_secret_is_rejected(self):
        ticket = issue_ticket('another-secret-value-0000000000000000', size=1024)
        with self.assertRaises(ValueError):
            verify_ticket(VALID_SECRET, ticket, max_size=2048)

    def test_size_ceiling_is_enforced(self):
        ticket = issue_ticket(VALID_SECRET, size=5000)
        with self.assertRaises(ValueError):
            verify_ticket(VALID_SECRET, ticket, max_size=1024)

    def test_expired_ticket_is_rejected(self):
        ticket = issue_ticket(VALID_SECRET, size=10, expires_at=1_000_000_000)
        with self.assertRaises(ValueError):
            verify_ticket(VALID_SECRET, ticket, max_size=1024)


class TicketEndpointTest(unittest.TestCase):
    """The web service mints the tickets the proxy verifies."""

    def setUp(self):
        import tempfile
        from flask_app import app, get_db
        self.app = app
        directory = tempfile.TemporaryDirectory(prefix='alienx-ticket-test-')
        self.addCleanup(directory.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(app.config, **{
            'TESTING': True,
            'DATABASE': str(Path(directory.name) / 'tickets.sqlite3'),
            'DATABASE_URL': None,
            'LITTERBOX_PROXY_SECRET': VALID_SECRET,
            'UPLOAD_RATE_LIMIT': 1000,
            'RATE_WINDOW_SECONDS': 600,
            'TRUST_PYTHONANYWHERE_PROXY': False,
            'TRUST_RENDER_PROXY': False,
        }))
        with app.app_context():
            get_db()
        self.client = app.test_client()

    def test_endpoint_returns_a_ticket_the_proxy_accepts(self):
        response = self.client.post('/api/litterbox-ticket',
                                    json={'size': 1024, 'expire': '1h'})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIsInstance(payload['ticket'], str)
        self.assertGreater(payload['expires_in'], 0)
        claims = verify_ticket(VALID_SECRET, payload['ticket'], max_size=2048)
        self.assertEqual(claims['size'], 1024)

    def test_endpoint_refuses_without_a_configured_proxy(self):
        with patch.dict(self.app.config, LITTERBOX_PROXY_SECRET=''):
            response = self.client.post('/api/litterbox-ticket',
                                        json={'size': 1024, 'expire': '1h'})
            self.assertEqual(response.status_code, 503)

    def test_endpoint_rejects_invalid_input(self):
        for body in ({'size': -1, 'expire': '1h'}, {'size': 'many', 'expire': '1h'},
                     {'size': 10_000_000_000, 'expire': '1h'},
                     {'size': 10, 'expire': 'bogus'}):
            response = self.client.post('/api/litterbox-ticket', json=body)
            self.assertEqual(response.status_code, 400, body)

    def test_endpoint_never_returns_the_shared_secret(self):
        response = self.client.post('/api/litterbox-ticket',
                                    json={'size': 1024, 'expire': '1h'})
        self.assertNotIn(VALID_SECRET, response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
