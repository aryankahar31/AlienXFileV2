import os
import re
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from flask_app import app

CHALLENGE_PATH = '/.well-known/openai-apps-challenge'
PUBLIC_PAGES = ('/privacy', '/terms', '/support')
# Claims the pages must not make: nothing here has been verified for this service.
FORBIDDEN_CLAIMS = (
    'GDPR', 'CCPA', 'HIPAA', 'SOC 2', 'ISO 27001', 'PCI', '99.9',
    'end-to-end encrypted', 'zero-knowledge', 'encrypted at rest',
    'we never store', 'we will notify', 'guaranteed uptime', 'California',
    'iron-clad', 'military-grade',
)


class PagesTest(unittest.TestCase):
    def setUp(self):
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(patch.dict(app.config, TESTING=True, SUPPORT_EMAIL=''))
        self.client = app.test_client()

    # ── public legal/support pages ────────────────────────────────────────────

    def test_public_pages_render_without_a_database(self):
        for path in PUBLIC_PAGES:
            with self.subTest(path=path):
                with patch('flask_app.get_db',
                           side_effect=AssertionError('Public pages must not need a database')):
                    response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.mimetype, 'text/html')
                html = response.get_data(as_text=True)
                self.assertIn('<h1>', html)
                # Indexable: no noindex header, index,follow meta, canonical URL.
                self.assertNotIn('noindex', response.headers.get('X-Robots-Tag', ''))
                self.assertIn('<meta name="robots" content="index, follow">', html)
                self.assertIn(f'<link rel="canonical" href="https://alienxfilev2.onrender.com{path}">',
                              html)
                self.assertIn('Content-Security-Policy', response.headers)
                # Cross-links between the sibling pages.
                for target in ('/', '/privacy', '/terms', '/support'):
                    self.assertIn(f'href="{target}"', html)
                # No internals ever reach the page.
                for needle in ('Traceback', '/Users/', 'sqlite3', 'DATABASE_URL',
                               'BLOB_READ_WRITE_TOKEN', 'SECRET'):
                    self.assertNotIn(needle, html)

    def test_privacy_policy_states_only_verifiable_facts(self):
        html = self.client.get('/privacy').get_data(as_text=True)
        # Facts we can point at in the code/config.
        for fact in ('no accounts', 'AES-GCM', 'PBKDF2', 'is never sent to the',
                     '12 hours, 1 day or 3 days', 'Neon', 'Vercel Blob',
                     'Litterbox', 'Fly.io', 'oaiusercontent.com', 'Google Fonts',
                     '10 minutes', '24 hours', 'do not set cookies', 'no ads',
                     'localStorage', 'Singapore'):
            with self.subTest(fact=fact):
                self.assertIn(fact, html)
        for claim in FORBIDDEN_CLAIMS:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, html)

    def test_terms_cover_required_elements(self):
        html = self.client.get('/terms').get_data(as_text=True)
        for element in ('Child sexual abuse material', 'Malware', 'copyright',
                        'at least <strong>13 years old</strong>', 'as is',
                        'as available', 'may remove', 'Support page',
                        'temporary sharing, not a backup', 'Limitation of liability'):
            with self.subTest(element=element):
                self.assertIn(element, html)
        for claim in FORBIDDEN_CLAIMS:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, html)

    def test_support_page_hides_contact_until_configured(self):
        html = self.client.get('/support').get_data(as_text=True)
        self.assertNotIn('mailto:', html)
        self.assertIn('not published at the moment', html)
        self.assertIn('Report abuse', html)
        self.assertIn('share code', html)
        with patch.dict(app.config, SUPPORT_EMAIL='help@example.com'):
            html = self.client.get('/support').get_data(as_text=True)
        self.assertIn('mailto:help@example.com', html)
        self.assertIn('help@example.com', html)
        for claim in FORBIDDEN_CLAIMS:
            self.assertNotIn(claim, html)

    def test_support_template_contains_no_hardcoded_address(self):
        source = Path(__file__).with_name('templates') / 'support.html'
        text = source.read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'[\w.+-]+@[\w-]+\.[A-Za-z]{2,}', text), [])
        self.assertIn('{{ support_email }}', text)

    # ── challenge route ───────────────────────────────────────────────────────

    def test_challenge_route_serves_exact_token_as_plain_text(self):
        with patch.dict(os.environ):
            os.environ.pop('OPENAI_APPS_CHALLENGE_TOKEN', None)
            response = self.client.get(CHALLENGE_PATH)
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.get_data(), b'')
            os.environ['OPENAI_APPS_CHALLENGE_TOKEN'] = 'challenge-token-123'
            response = self.client.get(CHALLENGE_PATH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/plain')
        self.assertEqual(response.get_data(), b'challenge-token-123')
        self.assertTrue(response.headers['Content-Type'].startswith('text/plain'))
        # The token path stays out of the crawlers' way.
        self.assertIn('noindex', response.headers.get('X-Robots-Tag', ''))
        # Unset again: back to a plain 404 with no body.
        response = self.client.get(CHALLENGE_PATH)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_data(), b'')

    def test_challenge_and_public_pages_do_not_disturb_discovery(self):
        robots = self.client.get('/robots.txt').get_data(as_text=True)
        sitemap = self.client.get('/sitemap.xml').get_data(as_text=True)
        self.assertIn('Sitemap: https://alienxfilev2.onrender.com/sitemap.xml', robots)
        self.assertNotIn('/privacy', sitemap)
        self.assertNotIn('openai-apps-challenge', robots)
        self.assertNotIn('openai-apps-challenge', sitemap)


if __name__ == '__main__':
    unittest.main()
