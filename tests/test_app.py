import unittest
import os
import json
from datetime import datetime, timedelta
import sys

# Add parent directory to path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_db, get_db_connection

class AlienXFileTestCase(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        # Use a temporary database for testing
        self.db_path = 'test_alienx.db'
        # Patch app to use test db
        import app as app_module
        app_module.DB_PATH = self.db_path

        self.app = app.test_client()
        init_db()

    def tearDown(self):
        # Remove the temporary database
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_index(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AlienX Instant Share', response.data)

    def test_upload_text(self):
        response = self.app.post('/upload', data={
            'mode': 'text',
            'text': 'This is a test text',
            'expire': '1h'
        })
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(len(data['uploads']), 1)
        key = data['uploads'][0]['key']

        # Verify it's in the DB
        conn = get_db_connection()
        row = conn.execute('SELECT * FROM files WHERE key = ?', (key,)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row['content'], 'This is a test text')

    def test_download_text(self):
        # Upload first
        response = self.app.post('/upload', data={
            'mode': 'text',
            'text': 'Downloadable text',
            'expire': '1h'
        })
        data = json.loads(response.data)
        key = data['uploads'][0]['key']

        # Download
        response = self.app.get(f'/download/{key}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Downloadable text', response.data)

    def test_invalid_key(self):
        response = self.app.get('/download/0000')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid or expired key!', response.data)

    def test_expired_content(self):
        # Manually insert expired content
        conn = get_db_connection()
        expired_time = datetime.utcnow() - timedelta(hours=1)
        conn.execute('INSERT INTO files (key, type, content, name, expires) VALUES (?, ?, ?, ?, ?)',
                     ('EXP1', 'text', 'Expired', 'Test', expired_time))
        conn.commit()
        conn.close()

        response = self.app.get('/download/EXP1')
        self.assertIn(b'Invalid or expired key!', response.data)

        # Check if it was cleaned up
        conn = get_db_connection()
        row = conn.execute('SELECT * FROM files WHERE key = ?', ('EXP1',)).fetchone()
        conn.close()
        self.assertIsNone(row)

if __name__ == '__main__':
    unittest.main()
