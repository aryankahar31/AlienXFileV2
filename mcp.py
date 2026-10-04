"""MCP (Model Context Protocol) endpoint for AlienXFile V2.

Transport: stateless Streamable HTTP — a single POST /mcp JSON-RPC 2.0
endpoint that answers with application/json (no SSE, no sessions, no ASGI).

Phase 1 auth: ALIENX_MCP_ENABLED gate plus an optional MCP_API_KEY bearer
check, all funneled through check_mcp_auth(). OAuth 2.1 (Phase 2) will be
added inside that single function later; see README.

Request bodies are never logged (they may contain user content).
"""

import base64
import binascii
import hmac
import json
import logging
import os
import re
import time
from io import BytesIO
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from flask import Blueprint, current_app, jsonify, request
from werkzeug.test import EnvironBuilder

logger = logging.getLogger(__name__)

mcp_bp = Blueprint('mcp', __name__)

SERVER_NAME = 'AlienXFile'
SERVER_VERSION = '2.0.0'
# Legacy handshake versions we answer in initialize, plus the modern
# (stateless) revision advertised through server/discover — this server is
# stateless, so it can serve both eras.
PROTOCOL_VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25')
MODERN_PROTOCOL_VERSION = '2026-07-28'
# Newest first: what server/discover advertises (modern revision + every
# legacy handshake revision this endpoint answers).
DISCOVER_SUPPORTED_VERSIONS = (MODERN_PROTOCOL_VERSION, '2025-11-25', '2025-06-18',
                               '2025-03-26', '2024-11-05')
DEFAULT_PROTOCOL_VERSION = '2025-11-25'
WEBSITE_URL = 'https://alienxfilev2.onrender.com'

# ChatGPT file params (openai/fileParams): the host injects a temporary
# provided-file object instead of file bytes. The signed download_url must
# never appear in any response, error message, or log line.
FILE_PARAM_HINT = ('Attach the file on ChatGPT desktop web and try again, or upload it on the '
                   'website at ' + WEBSITE_URL + ' and share the code it returns.')
FILE_PARAM_NO_URL = 'ChatGPT did not provide a downloadable file URL. ' + FILE_PARAM_HINT
DEFAULT_FILE_HOST_SUFFIXES = 'oaiusercontent.com,openai.com'
FILE_FETCH_TIMEOUT = (5, 15)
FILE_FETCH_CHUNK_BYTES = 64 * 1024
FILE_FETCH_MAX_HOPS = 3

CODE_RE = re.compile(r'[A-Za-z0-9]{3,20}')
BASE64_RE = re.compile(r'[A-Za-z0-9+/]*={0,2}')
LOOKUP_TOOLS = frozenset({'get_shared_content', 'get_shared_file', 'check_share'})
TOOL_NAMES = ('upload_file', 'share_text', 'get_shared_content', 'get_shared_file', 'check_share')
NOT_FOUND_MESSAGE = 'Share not found or expired.'
INVALID_CODE_MESSAGE = ('Invalid share code: must be 3-20 letters or numbers '
                        '(for example "12345").')
MAX_FILENAME = 255
BODY_OVERHEAD_BYTES = 65_536
DEFAULT_MCP_MAX_UPLOAD_BYTES = 26_214_400

# Friendly aliases accepted for the expires_in argument -> canonical keys of
# flask_app.expire_seconds. Anything else is rejected with EXPIRY_HELP.
EXPIRY_ALIASES = {
    '1h': '1h', '1 hour': '1h',
    '12h': '12h',
    '24h': '24h', '1d': '24h', '1 day': '24h', 'tomorrow': '24h',
    '72h': '72h', '3d': '72h', '3 days': '72h',
    '168h': '168h', '7d': '168h', '1 week': '168h',
}
DEFAULT_EXPIRY = '24h'
# "<N><unit>" / "<N> <unit>" durations normalised to hours. Only the five
# lifetimes above are ever produced — anything else is rejected.
EXPIRY_DURATION_RE = re.compile(r'^(\d+)\s*(hours?|hrs?|h|days?|d|weeks?|w)$')
EXPIRY_UNIT_HOURS = {'h': 1, 'hour': 1, 'hours': 1, 'hr': 1, 'hrs': 1,
                     'd': 24, 'day': 24, 'days': 24,
                     'w': 168, 'week': 168, 'weeks': 168}
EXPIRY_HOURS_TO_KEY = {1: '1h', 12: '12h', 24: '24h', 72: '72h', 168: '168h'}
EXPIRY_HELP = ('Allowed expires_in values: 1h, 12h, 24h, 72h, 168h (aliases: '
               '"1 hour", "1d", "1 day", "tomorrow", "3d", "3 days", "7d", "1 week"; '
               'spoken forms such as "12 hours", "12hr" or "3 day" are accepted only '
               'when they equal 1, 12, 24, 72 or 168 hours). '
               'The default is 24h.')

if os.environ.get('ALIENX_MCP_ENABLED', '0') == '1' and not os.environ.get('MCP_API_KEY', '').strip():
    logger.warning('MCP_API_KEY is not set: POST /mcp allows anonymous access (dev mode).')


class ToolError(Exception):
    """Tool failure reported as a JSON-RPC result with isError: true."""


# ── JSON-RPC plumbing (shared with flask_app's rate limiter) ─────────────────

def mcp_rpc_error(code, message, request_id=None, status=400, headers=None):
    """Return a JSON-RPC 2.0 error response tuple."""
    body = {'jsonrpc': '2.0', 'id': request_id,
            'error': {'code': code, 'message': message}}
    return jsonify(body), status, headers or {}


def mcp_rpc_id(payload):
    """Extract a JSON-RPC id from a parsed payload (None for notifications)."""
    if isinstance(payload, dict) and 'id' in payload and not isinstance(payload['id'], (dict, list)):
        return payload['id']
    return None


def _body_limit():
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
    # Exact base64 length of max_bytes plus JSON envelope overhead.
    return (max_bytes + 2) * 4 // 3 + BODY_OVERHEAD_BYTES


def mcp_request_payload():
    """Parse and cache the JSON-RPC body of a POST /mcp request.

    Returns (status, payload) with status 'ok', 'too_large', 'bad_json' or
    'not_object'. The body is read at most once and is never logged.
    """
    cached = request.environ.get('ALIENX_MCP_BODY')
    if cached is not None:
        return cached
    status, payload = 'ok', None
    limit = _body_limit()
    if request.content_length is not None and request.content_length > limit:
        status = 'too_large'
    else:
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = request.stream.read(min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        if len(raw) > limit:
            status = 'too_large'
        else:
            try:
                parsed = json.loads(raw)
            except ValueError:
                status = 'bad_json'
            else:
                if isinstance(parsed, dict):
                    payload = parsed
                else:
                    status = 'not_object'
    result = (status, payload)
    request.environ['ALIENX_MCP_BODY'] = result
    return result


def _rpc_result(request_id, result):
    return jsonify({'jsonrpc': '2.0', 'id': request_id, 'result': result}), 200


def _tool_result(request_id, text, is_error):
    return _rpc_result(request_id, {
        'content': [{'type': 'text', 'text': text}],
        'isError': is_error,
    })


# ── Auth (Phase 1; OAuth 2.1 is Phase 2 and will extend this function) ──────

def check_mcp_auth():
    """Return a response to send when the request is denied, else None."""
    api_key = (current_app.config.get('MCP_API_KEY') or '').strip()
    if not api_key:
        return None  # Anonymous dev mode (startup warning already logged).
    header = request.headers.get('Authorization', '')
    token = header[len('Bearer '):] if header.startswith('Bearer ') else ''
    if not token or not hmac.compare_digest(token.encode('utf-8'), api_key.encode('utf-8')):
        _, payload = mcp_request_payload()
        return mcp_rpc_error(-32001, 'Unauthorized: send Authorization: Bearer <MCP_API_KEY>.',
                             mcp_rpc_id(payload), 401, {'WWW-Authenticate': 'Bearer'})
    return None


def _allowed_origins():
    configured = current_app.config.get('MCP_ALLOWED_ORIGINS') or ()
    if isinstance(configured, str):
        configured = [part.strip() for part in configured.split(',')]
    return {origin for origin in configured if origin}


# ── HTTP endpoints ───────────────────────────────────────────────────────────

CORS_ALLOW_HEADERS = ('Content-Type, Authorization, Accept, MCP-Protocol-Version, '
                      'Mcp-Session-Id')


@mcp_bp.route('/mcp', methods=['GET'], strict_slashes=False,
               provide_automatic_options=False)
def mcp_get():
    if not current_app.config.get('MCP_ENABLED'):
        return jsonify(error='Not found.'), 404
    return mcp_rpc_error(-32600, 'Method Not Allowed: POST a JSON-RPC 2.0 body to this endpoint.',
                         status=405, headers={'Allow': 'POST'})


@mcp_bp.route('/mcp', methods=['OPTIONS'], strict_slashes=False)
def mcp_options():
    """CORS preflight for browser-based MCP clients (allowlist only)."""
    if not current_app.config.get('MCP_ENABLED'):
        return jsonify(error='Not found.'), 404
    origin = request.headers.get('Origin', '')
    if origin and origin not in _allowed_origins():
        return mcp_rpc_error(-32600, 'Origin is not allowed.', status=403)
    return '', 204, {'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                     'Access-Control-Allow-Headers': CORS_ALLOW_HEADERS,
                     'Access-Control-Max-Age': '600'}


@mcp_bp.after_request
def _mcp_cors_headers(response):
    """Echo Allow-Origin for allowlisted origins on every /mcp response."""
    origin = request.headers.get('Origin', '')
    if origin and origin in _allowed_origins():
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Expose-Headers'] = 'Mcp-Session-Id'
        vary = response.headers.get('Vary', '')
        parts = [part.strip() for part in vary.split(',') if part.strip()]
        if 'Origin' not in parts:
            parts.append('Origin')
        response.headers['Vary'] = ', '.join(parts)
    return response


@mcp_bp.route('/mcp', methods=['POST'], strict_slashes=False,
               provide_automatic_options=False)
def mcp_endpoint():
    if not current_app.config.get('MCP_ENABLED'):
        return jsonify(error='Not found.'), 404
    if request.mimetype != 'application/json':
        return mcp_rpc_error(-32600, 'Invalid Request: Content-Type must be application/json.',
                             status=415)
    origin = request.headers.get('Origin', '')
    if origin and origin not in _allowed_origins():
        return mcp_rpc_error(-32600, 'Origin is not allowed.', status=403)
    denied = check_mcp_auth()
    if denied is not None:
        return denied
    status, payload = mcp_request_payload()
    if status == 'too_large':
        return mcp_rpc_error(-32600, 'Request body too large.', status=413)
    request_id = mcp_rpc_id(payload)
    if status == 'bad_json':
        return mcp_rpc_error(-32700, 'Parse error: request body is not valid JSON.', request_id, 400)
    if status == 'not_object':
        return mcp_rpc_error(-32600, 'Invalid Request: JSON-RPC payload must be an object.',
                             request_id, 400)
    if payload.get('jsonrpc') != '2.0':
        return mcp_rpc_error(-32600, 'Invalid Request: jsonrpc must be "2.0".', request_id, 400)
    method = payload.get('method')
    if not isinstance(method, str) or not method:
        return mcp_rpc_error(-32600, 'Invalid Request: method must be a non-empty string.',
                             request_id, 400)
    if 'id' not in payload:
        # JSON-RPC notification (e.g. notifications/initialized): 202, no body.
        return '', 202
    if method == 'initialize':
        return _handle_initialize(payload, request_id)
    if method == 'server/discover':
        return _handle_discover(request_id)
    if method == 'ping':
        return _rpc_result(request_id, {})
    if method == 'tools/list':
        return _rpc_result(request_id, {'tools': _tool_definitions()})
    if method == 'tools/call':
        return _handle_tools_call(payload, request_id)
    return mcp_rpc_error(-32601, f'Method not found: {method}.', request_id, 200)


def _instructions():
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
    return (
        'AlienXFile shares temporary content. Tools: upload_file and share_text create shares; '
        'get_shared_content reads text/file content; get_shared_file returns metadata plus a '
        f'download link; check_share validates a code. Files are limited to {max_bytes} bytes '
        'decoded through MCP — larger files must be uploaded on the website at ' + WEBSITE_URL +
        ' and the resulting code shared instead. Passwords are not supported through MCP: '
        'password-protected shares can only be created and opened on the website. Shares expire '
        'automatically (default 24h).'
    )


def _handle_initialize(payload, request_id):
    params = payload.get('params')
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return mcp_rpc_error(-32602, 'Invalid params: initialize params must be an object.',
                             request_id, 200)
    requested = params.get('protocolVersion')
    if requested is not None and not isinstance(requested, str):
        return mcp_rpc_error(-32602, 'Invalid params: protocolVersion must be a string.',
                             request_id, 200)
    protocol = requested if requested in PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
    return _rpc_result(request_id, {
        'protocolVersion': protocol,
        'capabilities': {'tools': {}},
        'serverInfo': {'name': SERVER_NAME, 'title': SERVER_NAME, 'version': SERVER_VERSION},
        'instructions': _instructions(),
    })


def _handle_discover(request_id):
    """server/discover (MCP 2026-07-28): servers MUST implement this RPC."""
    return _rpc_result(request_id, {
        'resultType': 'complete',
        'supportedVersions': list(DISCOVER_SUPPORTED_VERSIONS),
        'capabilities': {'tools': {}},
        '_meta': {'io.modelcontextprotocol/serverInfo': {'name': SERVER_NAME,
                                                         'version': SERVER_VERSION}},
        'instructions': _instructions(),
    })


def _handle_tools_call(payload, request_id):
    params = payload.get('params')
    if not isinstance(params, dict):
        return mcp_rpc_error(-32602, 'Invalid params: params must be an object with a tool name.',
                             request_id, 200)
    name = params.get('name')
    if not isinstance(name, str) or not name:
        return mcp_rpc_error(-32602, 'Invalid params: name must be a non-empty string.',
                             request_id, 200)
    arguments = params.get('arguments', {})
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return mcp_rpc_error(-32602, 'Invalid params: arguments must be an object.',
                             request_id, 200)
    try:
        text = _dispatch_tool(name, arguments)
    except ToolError as exc:
        return _tool_result(request_id, str(exc), True)
    except Exception as exc:  # Never leak internals to the client or logs.
        logger.error('MCP tool %s failed (%s)', name, type(exc).__name__)
        return _tool_result(request_id, 'Internal error while running the tool. Please try again.',
                            True)
    return _tool_result(request_id, text, False)


# ── Tool catalogue ───────────────────────────────────────────────────────────

def _security_fields():
    """Tool security metadata (OpenAPI-style security scheme objects).

    Anonymous mode declares no scheme at all: "none" is not a valid OpenAPI
    security-scheme type, and clients treat a tool without security as public.
    """
    if (current_app.config.get('MCP_API_KEY') or '').strip():
        return ({'bearerAuth': {'type': 'http', 'scheme': 'bearer',
                                'description': 'Send Authorization: Bearer <MCP_API_KEY>.'}},
                [{'bearerAuth': []}])
    return {}, []


def _tool_definitions():
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
    schemes, security = _security_fields()
    expiry_field = {'type': 'string',
                    'description': 'Share lifetime: 1h, 12h, 24h (default), 72h or 168h. '
                                   'Friendly aliases such as "1 hour", "1d", "tomorrow", "3d" '
                                   'and "1 week" are accepted, as are spoken forms like '
                                   '"12 hours", "12hr" or "3 day" that equal one of those '
                                   'five lifetimes.'}
    custom_field = {'type': 'string', 'pattern': '^[A-Za-z0-9]{3,20}$',
                    'description': 'Optional custom share code: 3-20 letters or numbers.'}
    tools = [
        {
            'name': 'upload_file',
            'description': (
                'Upload a small file and create a temporary AlienXFile share; returns a short code '
                'plus public share/download URLs. Provide "file" for a ChatGPT attachment (the host '
                'passes download_url/file_id) or "content_base64" together with "filename" for raw '
                'bytes — exactly one of the two. Do NOT use for files larger than '
                f'{max_bytes} bytes — tell the user to upload at {WEBSITE_URL} instead and '
                'give you the resulting code. Do NOT use for password-protected shares: MCP never '
                'accepts passwords; use the website for that. Shares expire automatically.'
            ),
            'inputSchema': {
                'type': 'object',
                '$defs': {
                    'OpenAIFile': {
                        'type': 'object',
                        'properties': {
                            'download_url': {'type': 'string'},
                            'file_id': {'type': 'string'},
                            'mime_type': {'type': 'string'},
                            'file_name': {'type': 'string'},
                        },
                        'required': ['download_url', 'file_id'],
                        'additionalProperties': False,
                    },
                },
                'properties': {
                    'filename': {'type': 'string', 'maxLength': MAX_FILENAME,
                                 'description': 'File name only, no directories '
                                                '(path components are stripped, ".." is rejected). '
                                                'Used with content_base64.'},
                    'content_base64': {'type': 'string',
                                       'description': f'File bytes as standard base64 (no "data:" '
                                                      f'prefix, no line breaks). Decoded size limit '
                                                      f'{max_bytes} bytes. Use together with '
                                                      f'filename; do not combine with file.'},
                    'file': {'$ref': '#/$defs/OpenAIFile',
                             'description': 'ChatGPT file attachment injected by the host when the '
                                            'user attaches a file (declared via openai/fileParams). '
                                            'Do not fabricate this object; use content_base64 '
                                            'instead for bytes you already have.'},
                    'expires_in': expiry_field,
                    'custom_code': custom_field,
                },
                'required': [],
                'additionalProperties': False,
            },
            'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False},
            '_meta': {'openai/fileParams': ['file']},
            'securitySchemes': schemes,
            'security': security,
        },
        {
            'name': 'share_text',
            'description': (
                'Store text and create a temporary AlienXFile share; returns a short code plus '
                'public share/download URLs. Use when the user wants to share or hand off text of '
                f'up to {current_app.config.get("MAX_TEXT_LENGTH", 100_000)} characters. Do NOT use '
                'for password-protected shares (no password parameter — use the website) and not '
                'for files (use upload_file). The text expires automatically.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'text': {'type': 'string',
                             'description': 'The text to share.'},
                    'expires_in': expiry_field,
                    'custom_code': custom_field,
                },
                'required': ['text'],
                'additionalProperties': False,
            },
            'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False},
            'securitySchemes': schemes,
            'security': security,
        },
        {
            'name': 'get_shared_content',
            'description': (
                'Read a share by code: returns the full text for text shares and for small '
                'text-like files (up to 100 KB); for large or binary files returns metadata and a '
                'download_url only; for folder shares returns file names and sizes. '
                'Password-protected shares return metadata plus instructions to open the share URL '
                'in a browser (MCP never returns ciphertext). Use this to actually read content. '
                'Do NOT use it merely to check whether a code exists (use check_share) or only to '
                'fetch download links for files (use get_shared_file).'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {'code': {'type': 'string', 'pattern': '^[A-Za-z0-9]{3,20}$',
                                        'description': 'The share code (3-20 letters or numbers).'}},
                'required': ['code'],
                'additionalProperties': False,
            },
            'annotations': {'readOnlyHint': True, 'destructiveHint': False, 'openWorldHint': False},
            'securitySchemes': schemes,
            'security': security,
        },
        {
            'name': 'get_shared_file',
            'description': (
                'Get metadata for a share (type, name, size, expiry, password-protection flag) '
                'plus a public download_url, without downloading any bytes. Use when you only need '
                'information or a link. Do NOT use to read text content (use get_shared_content) '
                'or to check whether a code exists (use check_share). Never returns file bytes; '
                'password-protected shares return metadata plus instructions to open the share URL '
                'in a browser.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {'code': {'type': 'string', 'pattern': '^[A-Za-z0-9]{3,20}$',
                                        'description': 'The share code (3-20 letters or numbers).'}},
                'required': ['code'],
                'additionalProperties': False,
            },
            'annotations': {'readOnlyHint': True, 'destructiveHint': False, 'openWorldHint': False},
            'securitySchemes': schemes,
            'security': security,
        },
        {
            'name': 'check_share',
            'description': (
                'Check whether a share code exists and report its metadata: type, filename, size, '
                'expiry timestamp and whether it is password-protected. Read-only; use before '
                'relying on a code. Never returns content, salt, IV, ciphertext or storage URLs.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {'code': {'type': 'string', 'pattern': '^[A-Za-z0-9]{3,20}$',
                                        'description': 'The share code (3-20 letters or numbers).'}},
                'required': ['code'],
                'additionalProperties': False,
            },
            'annotations': {'readOnlyHint': True, 'destructiveHint': False, 'openWorldHint': False},
            'securitySchemes': schemes,
            'security': security,
        },
    ]
    if not schemes:
        # Anonymous mode: omit security metadata entirely rather than emit a
        # non-standard scheme type that strict clients may reject.
        for tool in tools:
            tool.pop('securitySchemes', None)
            tool.pop('security', None)
    return tools


# ── Argument helpers ─────────────────────────────────────────────────────────

def _require_string(args, key, *, required=True, max_length=None):
    value = args.get(key)
    if value is None:
        if required:
            raise ToolError(f'Missing required argument "{key}".')
        return None
    if not isinstance(value, str):
        raise ToolError(f'Argument "{key}" must be a string.')
    if max_length is not None and len(value) > max_length:
        raise ToolError(f'Argument "{key}" is too long (maximum {max_length} characters).')
    return value


def _share_code(args):
    code = _require_string(args, 'code')
    if not CODE_RE.fullmatch(code):
        raise ToolError(INVALID_CODE_MESSAGE)
    return code


def _custom_code(value):
    if value is None or value == '':
        return None
    if not isinstance(value, str) or not CODE_RE.fullmatch(value):
        raise ToolError('Custom code must be 3-20 letters or numbers (A-Z, a-z, 0-9).')
    return value


def _normalize_expiry(value):
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_EXPIRY
    if not isinstance(value, str):
        raise ToolError(f'Invalid expires_in. {EXPIRY_HELP}')
    text = value.strip().lower()
    canonical = EXPIRY_ALIASES.get(text)
    if canonical is None:
        match = EXPIRY_DURATION_RE.match(text)
        if match:
            hours = int(match.group(1)) * EXPIRY_UNIT_HOURS[match.group(2)]
            canonical = EXPIRY_HOURS_TO_KEY.get(hours)
    if canonical is None or canonical not in flask_app.expire_seconds:
        raise ToolError(f'Invalid expires_in: {value!r}. {EXPIRY_HELP}')
    return canonical


def _dump(payload):
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _share_urls(code):
    base = (current_app.config.get('MCP_PUBLIC_BASE_URL') or '').rstrip('/') or WEBSITE_URL
    return f'{base}/share/{code}', f'{base}/download/{code}'


def _is_encrypted(row):
    keys = row.keys()
    return bool(row['is_encrypted']) if 'is_encrypted' in keys else False


def _active_share(code):
    """Return the share row when the code exists and has not expired.

    Missing and expired codes are deliberately indistinguishable here so that
    every read tool reports the same message for both.
    """
    db = flask_app.get_db()
    row = flask_app.query(db, 'SELECT * FROM shares WHERE key = ?', (code,)).fetchone()
    if row is None or row['expires'] <= time.time():
        return None
    return row


def _any_share_row(code):
    db = flask_app.get_db()
    return flask_app.query(db, 'SELECT * FROM shares WHERE key = ?', (code,)).fetchone()


def _protected_payload(code, details, share_url, download_url):
    """Metadata-only response for password-protected shares (never ciphertext)."""
    return {
        'code': code,
        'type': details['type'],
        'filename': details['name'],
        'size': details['size'],
        'expires_at': details['expires'],
        'is_encrypted': True,
        'share_url': share_url,
        'download_url': download_url,
        'message': (f'This share is password-protected. Open {share_url} in a browser and enter '
                    'the password. MCP never receives passwords and never returns encrypted '
                    'content.'),
    }


# ── Existing-route reuse: the /upload view validates and stores everything ──

def _submit_upload(form):
    """Run the existing /upload route in a nested request context.

    This reuses all server-side validation, provider selection/fallback and
    save_share() without duplicating any storage logic.
    """
    builder = EnvironBuilder(method='POST', path='/upload', data=form)
    try:
        with flask_app.app.request_context(builder.get_environ()):
            result = flask_app.upload()
            if isinstance(result, tuple):
                body, status = result[0], result[1]
            else:
                body, status = result, getattr(result, 'status_code', 500)
            payload = body.get_json() if hasattr(body, 'get_json') else None
    finally:
        builder.close()
    return payload, status


def _submit_and_unwrap(form):
    payload, status = _submit_upload(form)
    if status == 200 and isinstance(payload, dict) and payload.get('success') and payload.get('uploads'):
        return payload['uploads'][0]
    message = 'The upload could not be completed.'
    if isinstance(payload, dict):
        message = payload.get('error') or '; '.join(payload.get('errors') or []) or message
    raise ToolError(message)


# ── Tool implementations ─────────────────────────────────────────────────────

def _dispatch_tool(name, arguments):
    if name == 'upload_file':
        return _tool_upload_file(arguments)
    if name == 'share_text':
        return _tool_share_text(arguments)
    if name == 'get_shared_content':
        return _tool_get_shared_content(arguments)
    if name == 'get_shared_file':
        return _tool_get_shared_file(arguments)
    if name == 'check_share':
        return _tool_check_share(arguments)
    raise ToolError(f'Unknown tool "{name}". Available tools: {", ".join(TOOL_NAMES)}.')


def _sanitize_filename(raw):
    if not raw.strip():
        raise ToolError('filename must be a non-empty string.')
    name = raw.strip()
    if '\x00' in name:
        raise ToolError('filename contains a null byte.')
    if len(name) > MAX_FILENAME:
        raise ToolError(f'filename is too long (maximum {MAX_FILENAME} characters).')
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ToolError('filename contains control characters.')
    if '..' in name:
        raise ToolError('filename must not contain ".." (path traversal is not allowed).')
    component = name.replace('\\', '/').split('/')[-1].strip()
    if not component or component in ('.', '..'):
        raise ToolError('filename must include a file name.')
    if Path(component).suffix.lower() in flask_app.banned_exts:
        raise ToolError(f'Files with the "{Path(component).suffix.lower()}" extension are blocked.')
    return component


def _decode_base64(content_b64, max_bytes):
    if len(content_b64) % 4:
        raise ToolError('content_base64 is not valid base64 (length must be a multiple of 4).')
    padding = len(content_b64) - len(content_b64.rstrip('='))
    expected = (len(content_b64) // 4) * 3 - padding
    if expected > max_bytes:
        raise ToolError(_oversize_message(max_bytes))
    if not BASE64_RE.fullmatch(content_b64):
        raise ToolError('content_base64 is not valid base64 '
                        '(expected standard alphabet A-Z a-z 0-9 + / with optional = padding).')
    try:
        data = base64.b64decode(content_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ToolError('content_base64 is not valid base64.')
    if len(data) > max_bytes:
        raise ToolError(_oversize_message(max_bytes))
    return data


def _oversize_message(max_bytes):
    return (f'File is too large for MCP upload (decoded limit {max_bytes} bytes). Upload it on '
            f'the website at {WEBSITE_URL} instead, then give me the share code it returns.')


# ── ChatGPT file params (openai/fileParams) ──────────────────────────────────

def _file_host_suffixes():
    """Allowed download_url host suffixes (strict dot-boundary matching)."""
    raw = os.environ.get('MCP_FILE_HOST_SUFFIXES', DEFAULT_FILE_HOST_SUFFIXES)
    suffixes = []
    for part in raw.split(','):
        part = part.strip().lower()
        if part.startswith('*.'):
            part = part[2:]
        part = part.lstrip('.')
        if part:
            suffixes.append(part)
    return tuple(suffixes)


def _parse_file_param(file_ref):
    """Validate the host-injected file object; return (download_url, file_name).

    Handles the known variants ChatGPT sends: the full object (desktop web),
    a bare file_id string (Actions normalization), and chat_upload:// string
    references (mobile). The URL is used only inside _fetch_chatgpt_file and
    must never be echoed anywhere.
    """
    if isinstance(file_ref, str) or not isinstance(file_ref, dict):
        # Bare file_id, chat_upload://..., ints, arrays, null-shaped refs.
        raise ToolError(FILE_PARAM_NO_URL)
    if 'download_url' not in file_ref or file_ref['download_url'] in (None, ''):
        raise ToolError(FILE_PARAM_NO_URL)
    download_url = file_ref['download_url']
    if not isinstance(download_url, str):
        raise ToolError(f'"download_url" must be a string. {FILE_PARAM_HINT}')
    for key in ('file_id', 'mime_type', 'file_name'):
        value = file_ref.get(key)
        if value is not None and not isinstance(value, str):
            raise ToolError(f'"{key}" must be a string. {FILE_PARAM_HINT}')
    file_name = file_ref.get('file_name')
    if isinstance(file_name, str) and not file_name.strip():
        file_name = None
    return download_url.strip(), file_name


def _safe_host_label(hostname):
    """Reduce a hostname to [a-z0-9.-] (max 100 chars) for a single log line.

    Never receives scheme, path, query, fragment, userinfo, or port: callers
    pass urlparse().hostname only, and the result is the sole URL-derived
    value that may appear in logs.
    """
    return re.sub(r'[^a-z0-9.-]', '', (hostname or '').lower())[:100]


def _validate_file_url(download_url, *, redirect=False):
    """Reject unsafe fetch targets: scheme, userinfo, port, host allowlist, IP.

    An allowlist rejection logs exactly one warning containing only the
    sanitized hostname and the reason code (`host_not_allowed` for the initial
    URL, `redirect_host_not_allowed` for a redirect hop) — never the full URL,
    query string, or any other component. All other rejections log nothing.
    """
    try:
        parsed = urlparse(download_url)
        port = parsed.port
    except ValueError:
        raise ToolError(f'The file download URL is not a valid URL. {FILE_PARAM_HINT}')
    if parsed.scheme != 'https' or not parsed.hostname or port not in (None, 443):
        raise ToolError(f'The file download URL must be an https URL on port 443. {FILE_PARAM_HINT}')
    if '@' in parsed.netloc:
        # Never embed credentials in the fetch URL (no auth headers either).
        raise ToolError(f'The file download host is not allowed. {FILE_PARAM_HINT}')
    hostname = parsed.hostname.lower()
    suffixes = _file_host_suffixes()
    if not any(hostname == suffix or hostname.endswith('.' + suffix) for suffix in suffixes):
        reason = 'redirect_host_not_allowed' if redirect else 'host_not_allowed'
        logger.warning('MCP upload_file file host rejected (%s): %s',
                       reason, _safe_host_label(hostname))
        raise ToolError(f'The file download host is not allowed. {FILE_PARAM_HINT}')
    if flask_app._is_private_host(hostname):
        # Fail-closed: private/reserved IPs and DNS failures are both rejected.
        raise ToolError(f'The file download host is not allowed. {FILE_PARAM_HINT}')
    return download_url


def _fetch_chatgpt_file(file_ref, max_bytes):
    """Stream a host-provided file param into memory. Returns (data, file_name).

    Safety: https only, strict host allowlist, private/DNS fail-closed check,
    allow_redirects=False with at most FILE_FETCH_MAX_HOPS manually validated
    hops, Content-Length pre-check plus a streamed size cap, TLS verification
    on, and no cookies or auth headers. The signed download_url never appears
    in responses or logs; allowlist rejections log one warning with only the
    sanitized hostname and reason code.
    """
    download_url, file_name = _parse_file_param(file_ref)
    url = _validate_file_url(download_url)
    data = bytearray()
    for hop in range(FILE_FETCH_MAX_HOPS + 1):
        try:
            response = requests.get(url, timeout=FILE_FETCH_TIMEOUT, allow_redirects=False,
                                    stream=True, verify=True,
                                    headers={'User-Agent': 'AlienXFile-MCP/2.0',
                                             'Accept': '*/*'})
        except requests.Timeout:
            logger.warning('MCP upload_file file fetch failed (Timeout)')
            raise ToolError(f'Could not download the attached file (timed out). {FILE_PARAM_HINT}')
        except requests.RequestException as exc:
            logger.warning('MCP upload_file file fetch failed (%s)', type(exc).__name__)
            raise ToolError(f'Could not download the attached file. {FILE_PARAM_HINT}')
        with response:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if not location:
                    raise ToolError(f'Could not download the attached file. {FILE_PARAM_HINT}')
                if hop == FILE_FETCH_MAX_HOPS:
                    raise ToolError(f'Could not download the attached file (too many redirects). '
                                    f'{FILE_PARAM_HINT}')
                url = _validate_file_url(urljoin(url, location), redirect=True)
                continue
            if response.status_code != 200:
                raise ToolError(f'Could not download the attached file '
                                f'(HTTP {response.status_code}). {FILE_PARAM_HINT}')
            content_length = response.headers.get('Content-Length')
            if content_length:
                try:
                    declared = int(content_length)
                except ValueError:
                    declared = None
                if declared is not None and declared > max_bytes:
                    raise ToolError(_oversize_message(max_bytes))
            for chunk in response.iter_content(FILE_FETCH_CHUNK_BYTES):
                if not chunk:
                    continue
                if len(data) + len(chunk) > max_bytes:
                    raise ToolError(_oversize_message(max_bytes))
                data.extend(chunk)
            break
    return bytes(data), file_name


def _tool_upload_file(args):
    file_ref = args.get('file')
    has_file = file_ref is not None
    has_base64 = args.get('content_base64') is not None
    if has_file and has_base64:
        raise ToolError('Provide only one of "file" (a ChatGPT attachment) or "content_base64" '
                        '(raw file bytes), not both.')
    if not has_file and not has_base64:
        raise ToolError('Provide one of "file" (a ChatGPT attachment) or "content_base64" '
                        '(raw file bytes) with "filename".')
    expiry = _normalize_expiry(args.get('expires_in'))
    custom_code = _custom_code(args.get('custom_code'))
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
    if has_file:
        # Validate shape and name first so a blocked extension fails before any download.
        _, file_name = _parse_file_param(file_ref)
        filename = _sanitize_filename(file_name) if file_name is not None else 'attachment'
        data, _ = _fetch_chatgpt_file(file_ref, max_bytes)
    else:
        raw_name = _require_string(args, 'filename')
        content_b64 = _require_string(args, 'content_base64')
        filename = _sanitize_filename(raw_name)
        data = _decode_base64(content_b64, max_bytes)
    form = {'mode': 'file', 'storageProvider': 'vercel', 'expire': expiry,
            'file': (BytesIO(data), filename)}
    if custom_code:
        form['customKey'] = custom_code
    share = _submit_and_unwrap(form)
    share_url, download_url = _share_urls(share['key'])
    return _dump({
        'success': True,
        'code': share['key'],
        'share_url': share_url,
        'download_url': download_url,
        'filename': share['name'],
        'size': share['size'],
        'expires_at': share['expires'],
        'expires_in': expiry,
    })


def _tool_share_text(args):
    text = _require_string(args, 'text')
    limit = current_app.config.get('MAX_TEXT_LENGTH', 100_000)
    if len(text) > limit:
        raise ToolError(f'Text is too long: {len(text)} characters (maximum {limit}).')
    normalized = text.replace('\r\n', '\n').strip()
    if not normalized:
        raise ToolError('Text cannot be blank.')
    if '\x00' in normalized:
        raise ToolError('Text cannot contain null characters.')
    expiry = _normalize_expiry(args.get('expires_in'))
    custom_code = _custom_code(args.get('custom_code'))
    form = {'mode': 'text', 'text': normalized, 'expire': expiry}
    if custom_code:
        form['customKey'] = custom_code
    share = _submit_and_unwrap(form)
    share_url, download_url = _share_urls(share['key'])
    return _dump({
        'success': True,
        'code': share['key'],
        'share_url': share_url,
        'download_url': download_url,
        'expires_at': share['expires'],
        'expires_in': expiry,
        'length': len(normalized),
    })


def _inline_text(code, details):
    """Return inline text for small text-like files via the preview endpoint."""
    if details['size'] > 100_000:
        return None
    if flask_app._preview_category(details['name'] or '') != 'code':
        return None
    result = flask_app.preview_file(code)
    if isinstance(result, tuple):
        body, status = result[0], result[1]
    else:
        body, status = result, getattr(result, 'status_code', 500)
    if status != 200 or not hasattr(body, 'get_json'):
        return None
    payload = body.get_json() or {}
    if payload.get('truncated'):
        return None
    text = payload.get('content')
    return text if isinstance(text, str) else None


def _tool_get_shared_content(args):
    code = _share_code(args)
    row = _active_share(code)
    if row is None:
        raise ToolError(NOT_FOUND_MESSAGE)
    details = flask_app.share_details(row)
    share_url, download_url = _share_urls(code)
    if _is_encrypted(row):
        return _dump(_protected_payload(code, details, share_url, download_url))
    base = {
        'code': code,
        'type': details['type'],
        'filename': details['name'],
        'size': details['size'],
        'expires_at': details['expires'],
        'is_encrypted': False,
        'share_url': share_url,
        'download_url': download_url,
    }
    if details['type'] == 'text':
        text = details.get('content') or ''
        base.update({'text': text, 'length': len(text)})
        return _dump(base)
    if details['type'] == 'folder':
        files = [{'name': entry.get('name'), 'size': entry.get('size')}
                 for entry in (details.get('files') or []) if isinstance(entry, dict)]
        base.update({'file_count': len(files), 'files': files})
        return _dump(base)
    text = _inline_text(code, details)
    if text is not None:
        base.update({'content_available': True, 'text': text})
    else:
        base.update({'content_available': False,
                     'message': 'Content is not returned inline (large or non-text file). '
                                'Use download_url to fetch it.'})
    return _dump(base)


def _tool_get_shared_file(args):
    code = _share_code(args)
    row = _active_share(code)
    if row is None:
        raise ToolError(NOT_FOUND_MESSAGE)
    details = flask_app.share_details(row)
    share_url, download_url = _share_urls(code)
    if _is_encrypted(row):
        return _dump(_protected_payload(code, details, share_url, download_url))
    return _dump({
        'code': code,
        'type': details['type'],
        'filename': details['name'],
        'size': details['size'],
        'expires_at': details['expires'],
        'is_encrypted': False,
        'share_url': share_url,
        'download_url': download_url,
    })


def _tool_check_share(args):
    code = _share_code(args)
    row = _any_share_row(code)
    if row is None:
        return _dump({'exists': False})
    expired = row['expires'] <= time.time()
    details = flask_app.share_details(row) if not expired else None
    payload = {
        'exists': True,
        'expired': expired,
        'type': row['type'],
        'filename': row['name'],
        'size': row['size'],
        'is_encrypted': _is_encrypted(row),
    }
    if details is not None:
        payload['expires_at'] = details['expires']
    else:
        import datetime as _dt
        payload['expires_at'] = _dt.datetime.fromtimestamp(
            row['expires'], _dt.timezone.utc).isoformat()
    return _dump(payload)


# Imported last: flask_app registers this blueprint at the end of its module,
# so the circular reference resolves before either module is used at runtime.
import flask_app  # noqa: E402
