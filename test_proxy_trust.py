"""Tests for reverse-proxy trust handling.

The application must only believe X-Forwarded-Proto when it really sits
behind the proxy that sets it, and it must never take the client address
from a client-supplied X-Forwarded-For header.
"""
import unittest

from flask import Flask, request

from flask_app import app as site_app
from flask_app import apply_proxy_trust


def _probe_app(**config):
    probe = Flask(__name__)
    probe.config.update(**config)
    apply_proxy_trust(probe)

    @probe.route('/probe')
    def probe_view():
        return {
            'secure': request.is_secure,
            'scheme': request.scheme,
            'remote_addr': request.remote_addr,
        }

    return probe


class ProxyTrustTest(unittest.TestCase):
    def test_forwarded_proto_is_ignored_without_a_trusted_proxy(self):
        probe = _probe_app(TRUST_RENDER_PROXY=False, TRUST_PYTHONANYWHERE_PROXY=False)
        client = probe.test_client()
        response = client.get('/probe', headers={'X-Forwarded-Proto': 'https'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()['secure'])
        self.assertEqual(response.get_json()['scheme'], 'http')

    def test_forwarded_proto_is_trusted_behind_a_known_proxy(self):
        probe = _probe_app(TRUST_RENDER_PROXY=True, TRUST_PYTHONANYWHERE_PROXY=False)
        client = probe.test_client()
        response = client.get('/probe', headers={'X-Forwarded-Proto': 'https'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['secure'])
        self.assertEqual(response.get_json()['scheme'], 'https')

    def test_forwarded_for_is_never_trusted(self):
        probe = _probe_app(TRUST_RENDER_PROXY=True, TRUST_PYTHONANYWHERE_PROXY=False)
        client = probe.test_client()
        response = client.get('/probe', headers={
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-For': '198.51.100.7',
        })
        self.assertNotEqual(response.get_json()['remote_addr'], '198.51.100.7')

    def test_apply_proxy_trust_reports_whether_it_engaged(self):
        self.assertFalse(apply_proxy_trust(
            _probe_app(TRUST_RENDER_PROXY=False, TRUST_PYTHONANYWHERE_PROXY=False)))
        self.assertTrue(apply_proxy_trust(
            _probe_app(TRUST_RENDER_PROXY=True, TRUST_PYTHONANYWHERE_PROXY=False)))
        self.assertTrue(apply_proxy_trust(
            _probe_app(TRUST_RENDER_PROXY=False, TRUST_PYTHONANYWHERE_PROXY=True)))


class HstsHeaderTest(unittest.TestCase):
    def test_hsts_is_emitted_for_real_https_requests(self):
        client = site_app.test_client()
        response = client.get('/', base_url='https://alienxfilev2.onrender.com')
        self.assertEqual(response.status_code, 200)
        self.assertIn('max-age=31536000', response.headers['Strict-Transport-Security'])

    def test_hsts_is_not_emitted_for_plain_http_requests(self):
        client = site_app.test_client()
        response = client.get('/', base_url='http://alienxfilev2.onrender.com')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Strict-Transport-Security', response.headers)

    def test_security_headers_survive_proxy_changes(self):
        client = site_app.test_client()
        response = client.get('/', base_url='https://alienxfilev2.onrender.com')
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])


if __name__ == '__main__':
    unittest.main()
