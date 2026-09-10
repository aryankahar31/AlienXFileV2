"""Run with ALIENX_TEST_DATABASE_URL pointing to a database allowing CREATE SCHEMA."""
import os
import subprocess
import sys
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

TEST_URL = os.environ.get('ALIENX_TEST_DATABASE_URL')
if TEST_URL:
    import psycopg
    import requests
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    from flask_app import app, get_db, query, transaction


@unittest.skipUnless(TEST_URL, 'Set ALIENX_TEST_DATABASE_URL to run isolated PostgreSQL tests')
class PostgresTest(unittest.TestCase):
    def setUp(self):
        schema = 'alienx_test_' + uuid.uuid4().hex
        self.dsn = make_conninfo(TEST_URL, options=f'-c search_path={schema}')
        admin = psycopg.connect(self.dsn, autocommit=True, connect_timeout=10)
        self.addCleanup(admin.close)
        admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        self.addCleanup(admin.execute, sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(patch.dict(app.config, TESTING=True, DATABASE_URL=self.dsn, BLOB_READ_WRITE_TOKEN='',
                                    DATABASE=':memory:', UPLOAD_RATE_LIMIT=1000,
                                    LOOKUP_RATE_LIMIT=1000, RATE_WINDOW_SECONDS=60,
                                    TRUST_PYTHONANYWHERE_PROXY=False, TRUST_RENDER_PROXY=False))
        self.now = 1_800_000_000.125
        self.clock = contexts.enter_context(patch('flask_app.time.time', return_value=self.now))
        contexts.enter_context(patch('flask_app.secrets.randbelow', side_effect=range(100_000)))
        contexts.enter_context(patch('requests.sessions.Session.request',
                               side_effect=AssertionError('Unexpected external HTTP')))
        self.post = contexts.enter_context(patch('flask_app.requests.post',
                                           side_effect=AssertionError('Unexpected upload')))
        # Opening a production connection must not silently initialize the schema.
        with app.app_context(), patch('psycopg.connect', wraps=psycopg.connect) as connect:
            db = get_db()
            self.assertIsInstance(db, psycopg.Connection)
            connect.assert_called_once_with(self.dsn, autocommit=True, row_factory=dict_row,
                                            connect_timeout=10, prepare_threshold=None)
            self.assertIsNone(db.execute("SELECT to_regclass('shares') AS table_name").fetchone()['table_name'])
        result = app.test_cli_runner().invoke(args=['init-db'])
        self.assertEqual(result.exit_code, 0, 'init-db failed in isolated test schema')
        self.client = app.test_client()

    def upload(self, text):
        return self.client.post('/upload', data={'mode': 'text', 'text': text, 'expire': '1h'})

    def test_persistence_across_contexts_and_fresh_process(self):
        with app.app_context():
            response = self.upload('persistent note')
            self.assertEqual(response.status_code, 200)
            key = response.get_json()['uploads'][0]['key']
        with app.app_context():
            row = query(get_db(), 'SELECT content FROM shares WHERE key = ?', (key,)).fetchone()
            self.assertEqual(row['content'], 'persistent note')
            self.assertIn(b'persistent note', self.client.get('/share/' + key).data)
        self.assertEqual(app.test_cli_runner().invoke(args=['init-db']).exit_code, 0)
        result = subprocess.run([sys.executable, '-B', '-c', '''
import os, sys
from unittest.mock import patch
from flask_app import app
app.config.update(DATABASE_URL=os.environ['ALIENX_TEST_DATABASE_URL'], DATABASE=':memory:',
                  TESTING=True, TRUST_PYTHONANYWHERE_PROXY=False, TRUST_RENDER_PROXY=False)
with patch('flask_app.time.time', return_value=float(sys.argv[2])), patch(
        'requests.sessions.Session.request', side_effect=AssertionError('Unexpected HTTP')):
    response = app.test_client().get('/share/' + sys.argv[1])
    assert response.status_code == 200, response.status_code
    assert b'persistent note' in response.data
''', key, str(self.now)], cwd=Path(__file__).resolve().parent,
            env={**os.environ, 'ALIENX_TEST_DATABASE_URL': self.dsn, 'DATABASE_URL': self.dsn},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, 'Fresh-process persistence check failed')

    def test_fractional_epoch_precision_and_expiry(self):
        self.assertEqual(self.upload('no\x00nulls').status_code, 400)
        response = self.upload('expires precisely')
        self.assertEqual(response.status_code, 200)
        share = response.get_json()['uploads'][0]
        self.assertEqual(datetime.fromisoformat(share['expires']).timestamp(), self.now + 3600)
        with app.app_context():
            db = get_db()
            row = db.execute('SELECT expires, pg_typeof(expires)::text AS kind FROM shares').fetchone()
            self.assertEqual((row['expires'], row['kind']), (self.now + 3600, 'double precision'))
            row = db.execute('SELECT started, pg_typeof(started)::text AS kind FROM rate_limits').fetchone()
            self.assertEqual((row['started'], row['kind']), (self.now, 'double precision'))
        self.clock.return_value = self.now + 3599.999
        self.assertEqual(self.client.get('/share/' + share['key']).status_code, 200)
        self.clock.return_value = self.now + 3600
        self.assertEqual(self.client.get('/share/' + share['key']).status_code, 410)
        self.assertEqual(self.client.get('/share/' + share['key']).status_code, 404)

    def test_collision_retry_exhaustion_and_transaction_recovery(self):
        with app.app_context():  # Keep the same connection even after exhausted retries.
            with patch('flask_app.secrets.randbelow', return_value=7):
                self.assertEqual(self.upload('original').status_code, 200)
            with patch('flask_app.secrets.randbelow', side_effect=[7, 8]) as random:
                response = self.upload('second')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['uploads'][0]['key'], '00008')
                self.assertEqual(random.call_count, 2)
            with patch('flask_app.secrets.randbelow', return_value=7) as random:
                response = self.upload('overwrite')
                self.assertEqual(response.status_code, 503)
                self.assertFalse(response.get_json()['success'])
                self.assertEqual(response.get_json()['uploads'], [])
                self.assertEqual(random.call_count, 100)
            db = get_db()
            rows = db.execute('SELECT key, content FROM shares ORDER BY key').fetchall()
            self.assertEqual(rows, [dict(key='00007', content='original'), dict(key='00008', content='second')])
            with self.assertRaisesRegex(ValueError, 'rollback'), transaction(db):
                query(db, 'DELETE FROM shares WHERE key = ?', ('00007',))
                raise ValueError('rollback')
            self.assertEqual(query(db, 'SELECT COUNT(*) AS n FROM shares').fetchone()['n'], 2)

    def test_parallel_writes_and_atomic_per_ip_limit(self):
        def upload(index):
            return app.test_client().post('/upload', data={'mode': 'text', 'text': str(index)},
                environ_overrides={'REMOTE_ADDR': f'198.51.100.{index % 2 + 1}'})

        with patch.dict(app.config, UPLOAD_RATE_LIMIT=4), ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(upload, range(24)))
        for parity in (0, 1):
            statuses = [r.status_code for r in responses[parity::2]]
            self.assertEqual(sorted(statuses), [200] * 4 + [429] * 8)
        shares = [r.get_json()['uploads'][0] for r in responses if r.status_code == 200]
        self.assertEqual(len({s['key'] for s in shares}), 8)
        self.assertTrue(all(int(r.headers['Retry-After']) > 0 for r in responses if r.status_code == 429))
        with app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) AS n FROM shares').fetchone()['n'], 8)
            rows = get_db().execute('SELECT ip, hits FROM rate_limits ORDER BY ip').fetchall()
            self.assertEqual(rows, [dict(ip=f'198.51.100.{i}', hits=12) for i in (1, 2)])
        self.clock.return_value += 60
        with patch.dict(app.config, UPLOAD_RATE_LIMIT=1):
            self.assertEqual(upload(0).status_code, 200)
            self.assertEqual(upload(2).status_code, 429)

    def test_small_file_provider_mock_and_canonical_urls(self):
        link = 'https://litter.catbox.moe/test.txt'
        provider = requests.Response()
        provider.status_code = 200
        provider._content = (' \n' + link + '\n').encode()
        provider._content_consumed = True
        self.post.side_effect = None
        self.post.return_value = provider
        response = self.client.post('/upload', data={
            'storageProvider': 'litterbox', 'file': (BytesIO(b'small file'), 'tiny.txt'),
        })
        self.assertEqual(response.status_code, 200)
        share = response.get_json()['uploads'][0]
        self.assertEqual((share['type'], share['size']), ('file', 10))
        self.assertEqual(share['storageProvider'], 'litterbox')
        with app.app_context():
            row = query(get_db(), 'SELECT provider FROM shares WHERE key = ?', (share['key'],)).fetchone()
            self.assertEqual(row['provider'], 'litterbox')
        self.assertEqual(share['page_url'], 'http://localhost/share/' + share['key'])
        self.assertEqual(share['link'], 'http://localhost/download/' + share['key'])
        page = self.client.get(share['page_url'])
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'tiny.txt', page.data)
        self.assertNotIn(link.encode(), page.data)
        direct = self.client.get(share['link'])
        self.assertEqual((direct.status_code, direct.location), (302, link))
        self.assertEqual(self.client.get('/qr/' + share['key']).mimetype, 'image/svg+xml')
        self.post.assert_called_once()

    def test_legacy_migration_and_old_seven_value_writer(self):
        columns = ('key', 'type', 'name', 'content', 'url', 'size', 'expires')
        blob_url = 'https://teststore.private.blob.vercel-storage.com/shares/' + 'a' * 32 + '/report.pdf'
        litterbox_url = 'https://litter.catbox.moe/legacy.txt'
        legacy = [
            ('00007', 'text', 'Shared Text', 'legacy note', None, 11, self.now + 3600),
            ('00008', 'file', 'report.pdf', None, blob_url, 9, self.now + 3600),
            ('00009', 'file', 'legacy.txt', None, litterbox_url, 1, self.now + 3600),
            ('00010', 'file', 'expired.txt', None, litterbox_url, 1, self.now - 1),
        ]
        with app.app_context():
            db = get_db()
            # setUp created this unique, empty schema; never alter a shared schema.
            self.assertEqual(db.execute('SELECT COUNT(*) AS n FROM shares').fetchone()['n'], 0)
            db.execute('ALTER TABLE shares DROP COLUMN provider')
            with transaction(db):
                for row in legacy:
                    query(db, '''INSERT INTO shares (key, type, name, content, url, size, expires)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)''', row)
                query(db, 'INSERT INTO rate_limits VALUES (?, ?, ?, ?)',
                      ('198.51.100.7', 'upload', self.now - 10, 3))
        for _ in range(2):
            result = app.test_cli_runner().invoke(args=['init-db'])
            self.assertEqual(result.exit_code, 0, 'Legacy migration failed in isolated test schema')
            with app.app_context():
                db = get_db()
                schema = db.execute('''SELECT column_name, data_type, column_default
                                       FROM information_schema.columns
                                       WHERE table_schema = current_schema() AND table_name = 'shares'
                                       ORDER BY ordinal_position''').fetchall()
                self.assertEqual([row['column_name'] for row in schema], [*columns, 'provider'])
                self.assertEqual(schema[-1]['data_type'], 'text')
                self.assertEqual(schema[-1]['column_default'], "'vercel'::text")
                rows = db.execute('SELECT * FROM shares ORDER BY key').fetchall()
                self.assertEqual([tuple(row[name] for name in columns) for row in rows], legacy)
                self.assertEqual([row['provider'] for row in rows], [None, 'vercel', 'litterbox', 'litterbox'])
                self.assertEqual(db.execute('SELECT * FROM rate_limits').fetchall(), [dict(
                    ip='198.51.100.7', action='upload', started=self.now - 10, hits=3,
                )])
                self.assertIsNotNone(db.execute("SELECT to_regclass('shares_expiry') AS idx").fetchone()['idx'])
        with app.app_context():
            db = get_db()
            old_worker_row = ('00011', 'file', 'report.pdf', None, blob_url, 9, self.now + 3600)
            # PostgreSQL permits old positional inserts to omit a trailing defaulted column.
            query(db, 'INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?, ?)', old_worker_row)
            row = query(db, 'SELECT * FROM shares WHERE key = ?', ('00011',)).fetchone()
            self.assertEqual(tuple(row[name] for name in columns), old_worker_row)
            self.assertEqual(row['provider'], 'vercel')
        self.assertIn(b'legacy note', self.client.get('/share/00007').data)
        self.assertEqual(self.client.get('/share/00008').status_code, 200)
        self.assertEqual(self.client.get('/download/00009').location, litterbox_url)
        self.assertEqual(self.client.get('/download/00010').status_code, 410)
        self.assertEqual(self.client.get('/download/00010').status_code, 404)
        self.post.assert_not_called()

    def test_outage_returns_safe_json_and_html_503(self):
        secret = 'postgresql://private_user:private_password@private_host/private_database'
        with patch('psycopg.connect', side_effect=psycopg.OperationalError(secret)):
            responses = [self.upload('unavailable')] + [self.client.get(path) for path in
                         ('/share/00007', '/download/00007', '/qr/00007')]
        for response in responses:
            self.assertEqual(response.status_code, 503)
            self.assertNotIn(b'private_', response.data)
            self.assertNotIn(self.dsn.encode(), response.data)
        self.assertFalse(responses[0].get_json()['success'])
        self.assertEqual(responses[0].get_json()['uploads'], [])
        for response in responses[1:]:
            self.assertEqual(response.mimetype, 'text/html')
            self.assertIn(b'<form', response.data)
        self.post.assert_not_called()


if __name__ == '__main__':
    unittest.main()
