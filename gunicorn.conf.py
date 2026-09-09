import os

bind = f'0.0.0.0:{os.environ.get("PORT", "8000")}'
workers = 1
threads = 2
timeout = 240

# Trust forwarded scheme only on Render's public ingress; do not use this for private-network callers.
render_web = os.environ.get('RENDER') == 'true' and os.environ.get('RENDER_SERVICE_TYPE') == 'web'
forwarded_allow_ips = '*' if render_web else ''
secure_scheme_headers = {'X-FORWARDED-PROTO': 'https'} if render_web else {}
forwarder_headers = ''
