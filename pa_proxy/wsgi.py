"""WSGI entry point for PythonAnywhere WSGI server configuration.

In the PythonAnywhere Web tab, set:
  WSGI configuration file: ~/alienxfile_litterbox/wsgi.py

In the same tab, under "Working directory" or env vars, add:
  LITTERBOX_PROXY_SECRET = <your-random-secret>
"""
import os
import sys

# Ensure venv site-packages are importable.
home = os.path.expanduser('~')
venv_site = os.path.join(home, 'alienxfile_litterbox', 'venv', 'lib', 'python3.12', 'site-packages')
if os.path.isdir(venv_site):
    sys.path.insert(0, venv_site)

# Set env var if not already set via the Web tab.
os.environ.setdefault('LITTERBOX_PROXY_SECRET', 'CHANGE_ME_TO_A_RANDOM_SECRET')

from app import app as application  # noqa: F401,E402
