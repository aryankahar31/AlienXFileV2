"""WSGI entry point for PythonAnywhere WSGI server configuration.

In the PythonAnywhere Web tab, set:
  WSGI configuration file: ~/alienxfile_litterbox/wsgi.py

In the same tab, under "Working directory" or env vars, add:
  LITTERBOX_PROXY_SECRET = <your-random-secret>

The secret is required: there is deliberately no fallback value, so a
misconfigured deployment fails to start instead of running with a guessable
credential.
"""
import os
import sys

# Ensure venv site-packages are importable.
home = os.path.expanduser('~')
venv_site = os.path.join(home, 'alienxfile_litterbox', 'venv', 'lib', 'python3.12', 'site-packages')
if os.path.isdir(venv_site):
    sys.path.insert(0, venv_site)

if not (os.environ.get('LITTERBOX_PROXY_SECRET') or '').strip():
    raise RuntimeError(
        'LITTERBOX_PROXY_SECRET is not set. Set it in the PythonAnywhere Web tab '
        'before starting the proxy; there is no default value.')

from app import app as application  # noqa: F401,E402
