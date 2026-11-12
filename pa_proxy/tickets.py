"""Signed upload tickets shared by AlienXFileV2 and the Litterbox proxy.

The browser uploads large files straight to the proxy so the bytes never pass
through the Render web service. That endpoint must not be anonymous, and the
shared proxy secret must never be shipped to a browser. Instead the web
service mints a short-lived, single-use ticket that proves "this upload is
allowed, for at most this many bytes, until this time". The ticket is signed
with a sub-key derived from LITTERBOX_PROXY_SECRET, so a ticket signature can
never be replayed as the proxy's own credential.

Only the standard library is used here: the proxy is deployed separately and
must not need any extra dependency.
"""
import base64
import hashlib
import hmac
import secrets
import time

TICKET_VERSION = 'v1'
TICKET_TTL_SECONDS = 900
MAX_TICKET_TTL_SECONDS = 3600
_KEY_CONTEXT = b'alienx-litterbox-upload-ticket-v1'


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _unb64(value: str) -> bytes:
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def derive_key(secret: str) -> bytes:
    """Derive the ticket signing key from the shared proxy secret."""
    if not isinstance(secret, str) or not secret:
        raise ValueError('A proxy secret is required.')
    return hmac.new(secret.encode('utf-8'), _KEY_CONTEXT, hashlib.sha256).digest()


def issue_ticket(secret: str, *, size: int = 0, expires_at=None, now=None,
                 ttl: int = TICKET_TTL_SECONDS) -> str:
    """Mint a ticket authorising one upload of at most `size` bytes."""
    now = time.time() if now is None else now
    expires_at = int(now + ttl) if expires_at is None else int(expires_at)
    nonce = secrets.token_urlsafe(12)
    size = int(size)
    payload = f'{TICKET_VERSION}.{expires_at}.{nonce}.{size}'
    signature = hmac.new(derive_key(secret), payload.encode('utf-8'), hashlib.sha256).digest()
    return f'{payload}.{_b64(signature)}'


def verify_ticket(secret: str, ticket, *, now=None, max_size: int = 0,
                  max_ttl: int = MAX_TICKET_TTL_SECONDS) -> dict:
    """Return the ticket claims or raise ValueError with a safe reason code.

    The reason codes never contain ticket material, so they can be logged.
    """
    now = time.time() if now is None else now
    if not isinstance(ticket, str) or not ticket or len(ticket) > 512:
        raise ValueError('missing_ticket')
    parts = ticket.split('.')
    if len(parts) != 5:
        raise ValueError('malformed_ticket')
    version, expires_raw, nonce, size_raw, signature = parts
    if version != TICKET_VERSION:
        raise ValueError('unsupported_ticket')
    try:
        expires_at = int(expires_raw)
        size = int(size_raw)
    except (TypeError, ValueError):
        raise ValueError('malformed_ticket')
    if not nonce or len(nonce) > 64:
        raise ValueError('malformed_ticket')
    payload = f'{version}.{expires_raw}.{nonce}.{size_raw}'
    expected = hmac.new(derive_key(secret), payload.encode('utf-8'), hashlib.sha256).digest()
    try:
        provided = _unb64(signature)
    except (ValueError, TypeError):
        raise ValueError('invalid_signature')
    if not hmac.compare_digest(expected, provided):
        raise ValueError('invalid_signature')
    if expires_at <= int(now):
        raise ValueError('expired_ticket')
    if expires_at > int(now) + max_ttl:
        raise ValueError('ticket_lifetime_too_long')
    if size < 0 or (max_size and size > max_size):
        raise ValueError('size_out_of_range')
    return {'expires_at': expires_at, 'nonce': nonce, 'size': size}
