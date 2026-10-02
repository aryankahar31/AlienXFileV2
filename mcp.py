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

from flask import Blueprint, current_app, jsonify, request
from werkzeug.test import EnvironBuilder

logger = logging.getLogger(__name__)

mcp_bp = Blueprint('mcp', __name__)

SERVER_NAME = 'AlienXFile'
SERVER_VERSION = '2.0.0'
PROTOCOL_VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18')
DEFAULT_PROTOCOL_VERSION = '2025-06-18'
WEBSITE_URL = 'https://alienxfilev2.onrender.com'

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
EXPIRY_HELP = ('Allowed expires_in values: 1h, 12h, 24h, 72h, 168h (aliases: '
               '"1 hour", "1d", "1 day", "tomorrow", "3d", "3 days", "7d", "1 week"). '
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

@mcp_bp.route('/mcp', methods=['GET'])
def mcp_get():
    if not current_app.config.get('MCP_ENABLED'):
        return jsonify(error='Not found.'), 404
    return mcp_rpc_error(-32600, 'Method Not Allowed: POST a JSON-RPC 2.0 body to this endpoint.',
                         status=405, headers={'Allow': 'POST'})


@mcp_bp.route('/mcp', methods=['POST'])
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
    if method == 'ping':
        return _rpc_result(request_id, {})
    if method == 'tools/list':
        return _rpc_result(request_id, {'tools': _tool_definitions()})
    if method == 'tools/call':
        return _handle_tools_call(payload, request_id)
    return mcp_rpc_error(-32601, f'Method not found: {method}.', request_id, 200)


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
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
    instructions = (
        'AlienXFile shares temporary content. Tools: upload_file and share_text create shares; '
        'get_shared_content reads text/file content; get_shared_file returns metadata plus a '
        f'download link; check_share validates a code. Files are limited to {max_bytes} bytes '
        'decoded through MCP — larger files must be uploaded on the website at ' + WEBSITE_URL +
        ' and the resulting code shared instead. Passwords are not supported through MCP: '
        'password-protected shares can only be created and opened on the website. Shares expire '
        'automatically (default 24h).'
    )
    return _rpc_result(request_id, {
        'protocolVersion': protocol,
        'capabilities': {'tools': {}},
        'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
        'instructions': instructions,
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
    if (current_app.config.get('MCP_API_KEY') or '').strip():
        return ({'bearerAuth': {'type': 'http', 'scheme': 'bearer',
                                'description': 'Send Authorization: Bearer <MCP_API_KEY>.'}},
                [{'bearerAuth': []}])
    return ({'noauth': {'type': 'none',
                        'description': 'No authentication required (anonymous dev mode).'}},
            [{}])


def _tool_definitions():
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
    schemes, security = _security_fields()
    expiry_field = {'type': 'string',
                    'description': 'Share lifetime: 1h, 12h, 24h (default), 72h or 168h. '
                                   'Friendly aliases such as "1 hour", "1d", "tomorrow", "3d" '
                                   'and "1 week" are accepted.'}
    custom_field = {'type': 'string', 'pattern': '^[A-Za-z0-9]{3,20}$',
                    'description': 'Optional custom share code: 3-20 letters or numbers.'}
    tools = [
        {
            'name': 'upload_file',
            'description': (
                'Upload a small file (base64 content) and create a temporary AlienXFile share; '
                'returns a short code plus public share/download URLs. Use when the user provides '
                'a file to share. Do NOT use for files larger than '
                f'{max_bytes} bytes decoded — tell the user to upload at {WEBSITE_URL} instead and '
                'give you the resulting code. Do NOT use for password-protected shares: MCP never '
                'accepts passwords; use the website for that. Shares expire automatically.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'filename': {'type': 'string', 'maxLength': MAX_FILENAME,
                                 'description': 'File name only, no directories '
                                                '(path components are stripped, ".." is rejected).'},
                    'content_base64': {'type': 'string',
                                       'description': f'File bytes as standard base64 (no "data:" '
                                                      f'prefix, no line breaks). Decoded size limit '
                                                      f'{max_bytes} bytes.'},
                    'expires_in': expiry_field,
                    'custom_code': custom_field,
                },
                'required': ['filename', 'content_base64'],
                'additionalProperties': False,
            },
            'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False},
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
    canonical = EXPIRY_ALIASES.get(value.strip().lower())
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


def _tool_upload_file(args):
    raw_name = _require_string(args, 'filename')
    content_b64 = _require_string(args, 'content_base64')
    expiry = _normalize_expiry(args.get('expires_in'))
    custom_code = _custom_code(args.get('custom_code'))
    filename = _sanitize_filename(raw_name)
    max_bytes = current_app.config.get('MCP_MAX_UPLOAD_BYTES', DEFAULT_MCP_MAX_UPLOAD_BYTES)
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
