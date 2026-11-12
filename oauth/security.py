import base64
import hashlib
import hmac
import re
import secrets
from functools import lru_cache
from urllib.parse import unquote, urlparse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .constants import DEFAULT_SCOPES, SUPPORTED_SCOPES

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
CODE_RE = re.compile(r'[A-Za-z0-9._~-]{43,128}')
CHALLENGE_RE = re.compile(r'[A-Za-z0-9_-]{43,128}')
PKCE_RE = re.compile(r'[A-Za-z0-9._~-]{43,128}')


@lru_cache(maxsize=1)
def _dummy_password_hash():
    return PASSWORD_HASHER.hash('alienxfile-dummy-password-not-used')


def hash_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError('Password must be a non-empty string.')
    return PASSWORD_HASHER.hash(password)


def verify_password(password, password_hash):
    if not isinstance(password, str) or not isinstance(password_hash, str) or not password_hash:
        return False
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def verify_owner_password(username, password, owner_username, owner_hash):
    username_ok = hmac.compare_digest(str(username or ''), str(owner_username or ''))
    candidate = owner_hash if username_ok else _dummy_password_hash()
    password_ok = verify_password(password, candidate)
    return username_ok and password_ok


def hash_token(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def new_token(nbytes=32, prefix=''):
    return prefix + secrets.token_urlsafe(nbytes)


def new_access_token():
    return new_token(32, 'axa_')


def new_refresh_token():
    return new_token(48, 'axr_')


def new_authorization_code():
    return new_token(32, 'axc_')


def new_session_token():
    return new_token(32, 'axs_')


def new_client_id():
    return 'axclient_' + secrets.token_hex(16)


def new_client_secret():
    return 'axsecret_' + secrets.token_urlsafe(32)


def new_family_id():
    return secrets.token_hex(16)


def new_csrf_token():
    return secrets.token_urlsafe(32)


def parse_scope(value, default=DEFAULT_SCOPES):
    if value is None or not str(value).strip():
        return list(default)
    scopes = []
    for part in str(value).split():
        if part not in SUPPORTED_SCOPES:
            raise ValueError(f'Unsupported scope: {part}')
        if part not in scopes:
            scopes.append(part)
    if not scopes:
        raise ValueError('At least one scope is required.')
    return scopes


def scope_string(scopes):
    return ' '.join(scopes)


def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def verify_pkce(verifier, challenge):
    if not isinstance(verifier, str) or not PKCE_RE.fullmatch(verifier):
        return False
    if not isinstance(challenge, str) or not challenge:
        return False
    return hmac.compare_digest(pkce_challenge(verifier), challenge)


def csrf_serializer(secret):
    return URLSafeTimedSerializer(secret, salt='alienx-oauth-csrf')


def csrf_issue(secret):
    return csrf_serializer(secret).dumps(secrets.token_urlsafe(16))


def csrf_verify(form_token, cookie_token, secret, max_age=900):
    if not form_token or not cookie_token:
        return False
    try:
        form_value = csrf_serializer(secret).loads(form_token, max_age=max_age)
        cookie_value = csrf_serializer(secret).loads(cookie_token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return False
    return hmac.compare_digest(str(form_value), str(cookie_value))


def validate_redirect_uri(value):
    if not isinstance(value, str) or not value or len(value) > 2000:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    if parsed.fragment or '@' in parsed.netloc:
        return False
    if parsed.scheme == 'https':
        return bool(parsed.hostname) and port in (None, 443)
    if parsed.scheme == 'http':
        return parsed.hostname in ('localhost', '127.0.0.1', '::1') and port not in (0,)
    return False


def is_cimd_client_id(value):
    if not isinstance(value, str) or len(value) > 2000:
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme == 'https' and bool(parsed.hostname)
            and port in (None, 443) and bool(parsed.path) and parsed.path != '/'
            and not parsed.query and not parsed.fragment and '@' not in parsed.netloc)


def safe_next_path(value):
    if not isinstance(value, str):
        return '/account'
    decoded = unquote(value)
    if not decoded.startswith('/') or decoded.startswith('//') or '\\' in decoded:
        return '/account'
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded):
        return '/account'
    return value


def sanitize_client_name(value):
    if not isinstance(value, str):
        return 'MCP Client'
    name = ''.join(ch for ch in value if ord(ch) >= 32 and ord(ch) != 127).strip()
    return name[:200] or 'MCP Client'
