import base64
import hmac
import json
import time
from urllib.parse import parse_qsl, quote, unquote_plus, urlencode, urlparse, urlunparse

import requests
from flask import (Blueprint, current_app, jsonify, redirect, render_template, request,
                   url_for)

from . import store
from .constants import DEFAULT_SCOPES, SCOPE_DESCRIPTIONS, SUPPORTED_SCOPES
from .metadata import (audience, authorization_server_metadata, issuer, oauth_enabled,
                       owner_configured, protected_resource_metadata)
from .security import (CHALLENGE_RE, csrf_issue, csrf_verify, hash_token,
                       is_cimd_client_id, new_client_id, new_client_secret, new_family_id,
                       parse_scope, safe_next_path, sanitize_client_name, scope_string,
                       validate_redirect_uri, verify_owner_password, verify_pkce)

oauth_bp = Blueprint('oauth', __name__)

SESSION_COOKIE = 'alienx_owner_session'
LOGIN_CSRF_COOKIE = 'alienx_login_csrf'
CORS_ENDPOINTS = {'oauth.metadata', 'oauth.protected_resource',
                  'oauth.token', 'oauth.register', 'oauth.revoke'}


def _fa():
    import flask_app
    return flask_app


def _no_store(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


def _json(payload, status=200, headers=None):
    response = jsonify(payload)
    response.status_code = status
    for name, value in (headers or {}).items():
        response.headers[name] = value
    return _no_store(response)


def _oauth_error(error, description, status=400, headers=None):
    return _json({'error': error, 'error_description': description}, status, headers)


def _render_error(message, status=400):
    return render_template('oauth_error.html', error=message), status


def _append_query(uri, params):
    parsed = urlparse(uri)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
             if key not in params]
    query.extend(params.items())
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(query, quote_via=quote), ''))


def _authorization_redirect(redirect_uri, params):
    values = dict(params)
    values['iss'] = issuer()
    return redirect(_append_query(redirect_uri, values), code=302)


def _authorization_error(redirect_uri, error, description, state=None):
    params = {'error': error, 'error_description': description}
    if state:
        params['state'] = state
    return _authorization_redirect(redirect_uri, params)


def _session_token():
    return request.cookies.get(SESSION_COOKIE)


def _session():
    session = store.get_session(_session_token())
    if session is None:
        return None
    if session['owner'] != current_app.config.get('OWNER_USERNAME'):
        return None
    return session


def _set_session_cookie(response, token, ttl):
    response.set_cookie(SESSION_COOKIE, token, max_age=ttl, httponly=True,
                        secure=bool(current_app.config.get('OAUTH_COOKIE_SECURE')),
                        samesite='Lax', path='/')
    return response


def _clear_session_cookie(response):
    response.delete_cookie(SESSION_COOKIE, path='/')
    return response


def _login_redirect(next_url=None):
    target = next_url or request.full_path
    return redirect('/login?next=' + quote(target, safe=''), code=303)


def _client_redirects(client):
    try:
        value = json.loads(client.get('redirect_uris') or '[]')
    except (TypeError, ValueError):
        return []
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _client_scopes(client):
    raw = (client or {}).get('scope') or ''
    return [part for part in str(raw).split() if part in SUPPORTED_SCOPES]


def _fetch_cimd(client_id):
    if not current_app.config.get('OAUTH_CIMD_ENABLED', True):
        raise ValueError('Client metadata documents are disabled.')
    if not is_cimd_client_id(client_id):
        raise ValueError('Invalid client metadata URL.')
    parsed = urlparse(client_id)
    if _fa()._is_private_host(parsed.hostname):
        raise ValueError('Client metadata host is not allowed.')
    response = requests.get(client_id, timeout=(5, 10), allow_redirects=False,
                            headers={'Accept': 'application/json',
                                     'User-Agent': 'AlienXFile-OAuth/1.0'})
    with response:
        if response.status_code != 200:
            raise ValueError('Client metadata is unavailable.')
        declared = response.headers.get('Content-Length')
        if declared:
            try:
                if int(declared) > 65_536:
                    raise ValueError('Client metadata is too large.')
            except ValueError:
                raise ValueError('Invalid client metadata length.')
        raw = bytearray()
        for chunk in response.iter_content(8192):
            raw.extend(chunk)
            if len(raw) > 65_536:
                raise ValueError('Client metadata is too large.')
    try:
        document = json.loads(bytes(raw))
    except (TypeError, ValueError):
        raise ValueError('Client metadata is not valid JSON.')
    if not isinstance(document, dict) or document.get('client_id') != client_id:
        raise ValueError('Client metadata client_id does not match the URL.')
    uris = document.get('redirect_uris')
    if (not isinstance(uris, list) or not 1 <= len(uris) <= 10
            or not all(validate_redirect_uri(uri) for uri in uris)):
        raise ValueError('Client metadata redirect_uris are invalid.')
    return document


def _store_cimd(client_id, document):
    grant_types = document.get('grant_types')
    if not isinstance(grant_types, list) or not grant_types:
        grant_types = ['authorization_code', 'refresh_token']
    grant_types = [item for item in grant_types
                   if item in ('authorization_code', 'refresh_token')]
    if 'authorization_code' not in grant_types:
        grant_types.insert(0, 'authorization_code')
    response_types = document.get('response_types')
    if not isinstance(response_types, list) or 'code' not in response_types:
        response_types = ['code']
    try:
        scopes = parse_scope(document.get('scope'), default=DEFAULT_SCOPES)
    except ValueError as exc:
        raise ValueError(str(exc))
    metadata = {key: document[key] for key in
                ('client_uri', 'logo_uri', 'contacts', 'tos_uri', 'policy_uri',
                 'software_id', 'software_version') if key in document}
    return store.upsert_client(
        client_id, sanitize_client_name(document.get('client_name')), document['redirect_uris'],
        grant_types, ['code'], 'none', scope_string(scopes), 'cimd', metadata, None)


def _resolve_client(client_id):
    client = store.get_client(client_id)
    if client is None and is_cimd_client_id(client_id):
        try:
            client = _store_cimd(client_id, _fetch_cimd(client_id))
        except (requests.RequestException, ValueError) as exc:
            _fa().logger.warning('OAuth client metadata fetch rejected (%s)', type(exc).__name__)
            return None
    elif client is not None and client.get('source') == 'cimd':
        if client['updated_at'] < time.time() - 3600:
            try:
                client = _store_cimd(client_id, _fetch_cimd(client_id))
            except (requests.RequestException, ValueError):
                pass
    return client


def _authenticate_client():
    header = request.headers.get('Authorization', '')
    basic = None
    if header.startswith('Basic '):
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode('utf-8')
            basic_id, basic_secret = decoded.split(':', 1)
            basic = (unquote_plus(basic_id), unquote_plus(basic_secret))
        except (ValueError, UnicodeDecodeError):
            return None, 'invalid_client', 'Malformed client authentication.'
    client_id = basic[0] if basic else (request.form.get('client_id') or '')
    secret = basic[1] if basic else (request.form.get('client_secret') or '')
    if basic and request.form.get('client_id') and request.form['client_id'] != basic[0]:
        return None, 'invalid_client', 'Conflicting client identifiers.'
    client = _resolve_client(client_id)
    if client is None:
        return None, 'invalid_client', 'Unknown OAuth client.'
    stored_hash = client.get('client_secret_hash')
    if stored_hash:
        if not secret or not hmac.compare_digest(hash_token(secret), stored_hash):
            return None, 'invalid_client', 'Client authentication failed.'
    elif secret:
        return None, 'invalid_client', 'Public clients must not send a client secret.'
    return client, None, None


def _validate_registration(payload):
    if not isinstance(payload, dict):
        return None, 'Request body must be a JSON object.'
    uris = payload.get('redirect_uris')
    if (not isinstance(uris, list) or not 1 <= len(uris) <= 10
            or not all(validate_redirect_uri(uri) for uri in uris)):
        return None, 'redirect_uris must contain 1-10 valid HTTPS (or localhost HTTP) URLs.'
    grant_types = payload.get('grant_types', ['authorization_code', 'refresh_token'])
    if (not isinstance(grant_types, list)
            or not set(grant_types).issubset({'authorization_code', 'refresh_token'})
            or 'authorization_code' not in grant_types):
        return None, 'grant_types must contain authorization_code and only supported grants.'
    response_types = payload.get('response_types', ['code'])
    if not isinstance(response_types, list) or response_types != ['code']:
        return None, 'response_types must be ["code"].'
    method = payload.get('token_endpoint_auth_method', 'none')
    if method not in ('none', 'client_secret_basic', 'client_secret_post'):
        return None, 'Unsupported token_endpoint_auth_method.'
    try:
        scopes = parse_scope(payload.get('scope'), default=DEFAULT_SCOPES)
    except ValueError as exc:
        return None, str(exc)
    return {
        'client_name': sanitize_client_name(payload.get('client_name')),
        'redirect_uris': uris,
        'grant_types': grant_types,
        'response_types': ['code'],
        'token_endpoint_auth_method': method,
        'scope': scopes,
    }, None


def _validate_authorization(params, client):
    redirect_uri = params.get('redirect_uri') or ''
    if redirect_uri not in _client_redirects(client):
        return None, 'invalid_request', 'redirect_uri is not registered for this client.'
    if (params.get('response_type') or '') != 'code':
        return None, 'unsupported_response_type', 'Only response_type=code is supported.'
    challenge = params.get('code_challenge') or ''
    if not CHALLENGE_RE.fullmatch(challenge):
        return None, 'invalid_request', 'A valid PKCE code_challenge is required.'
    if (params.get('code_challenge_method') or '') != 'S256':
        return None, 'invalid_request', 'code_challenge_method must be S256.'
    try:
        scopes = parse_scope(params.get('scope'), default=())
    except ValueError as exc:
        return None, 'invalid_scope', str(exc)
    allowed = _client_scopes(client) or list(DEFAULT_SCOPES)
    if not scopes:
        scopes = allowed
    if not set(scopes).issubset(allowed):
        return None, 'invalid_scope', 'The client is not registered for the requested scopes.'
    resource = params.get('resource') or audience()
    if resource != audience():
        return None, 'invalid_target', 'The requested resource is not served by this MCP endpoint.'
    state = params.get('state')
    if state is not None:
        if not isinstance(state, str) or len(state) > 512 or any(
                ord(ch) < 32 or ord(ch) == 127 for ch in state):
            return None, 'invalid_request', 'Invalid state parameter.'
    return {
        'redirect_uri': redirect_uri,
        'code_challenge': challenge,
        'scopes': scopes,
        'resource': resource,
        'state': state or '',
        'scope_text': scope_string(scopes),
    }, None, None


def _hidden_authorization_params(values):
    return {
        'client_id': values['client_id'],
        'redirect_uri': values['redirect_uri'],
        'response_type': 'code',
        'code_challenge': values['code_challenge'],
        'code_challenge_method': 'S256',
        'scope': values['scope_text'],
        'resource': values['resource'],
        'state': values['state'],
    }


def _metadata_disabled():
    return _json({'error': 'not_found'}, 404)


@oauth_bp.route('/.well-known/oauth-authorization-server', methods=['GET'])
def metadata():
    if not oauth_enabled():
        return _metadata_disabled()
    return _json(authorization_server_metadata())


@oauth_bp.route('/.well-known/oauth-protected-resource', methods=['GET'])
@oauth_bp.route('/.well-known/oauth-protected-resource/mcp', methods=['GET'])
def protected_resource():
    if not oauth_enabled():
        return _metadata_disabled()
    return _json(protected_resource_metadata())


@oauth_bp.route('/oauth/register', methods=['POST'])
def register():
    if not oauth_enabled():
        return _json({'error': 'not_found'}, 404)
    if not current_app.config.get('OAUTH_DCR_ENABLED', True):
        return _oauth_error('invalid_client_metadata', 'Dynamic client registration is disabled.', 403)
    payload = request.get_json(silent=True)
    values, error = _validate_registration(payload)
    if error:
        return _oauth_error('invalid_client_metadata', error)
    client_id = new_client_id()
    secret = new_client_secret() if values['token_endpoint_auth_method'] != 'none' else None
    metadata = {key: payload[key] for key in
                ('client_uri', 'logo_uri', 'contacts', 'tos_uri', 'policy_uri',
                 'software_id', 'software_version') if key in payload}
    store.upsert_client(client_id, values['client_name'], values['redirect_uris'],
                        values['grant_types'], values['response_types'],
                        values['token_endpoint_auth_method'], scope_string(values['scope']),
                        'dcr', metadata, hash_token(secret) if secret else None)
    result = {
        'client_id': client_id,
        'client_name': values['client_name'],
        'redirect_uris': values['redirect_uris'],
        'grant_types': values['grant_types'],
        'response_types': values['response_types'],
        'token_endpoint_auth_method': values['token_endpoint_auth_method'],
        'scope': scope_string(values['scope']),
        'client_id_issued_at': int(time.time()),
        'client_secret_expires_at': 0,
    }
    if secret:
        result['client_secret'] = secret
    return _json(result, 201)


@oauth_bp.route('/oauth/authorize', methods=['GET'])
def authorize():
    if not oauth_enabled():
        return _render_error('Not found.', 404)
    if not owner_configured():
        return _render_error('The owner account is not configured yet.', 503)
    client_id = request.args.get('client_id') or ''
    client = _resolve_client(client_id)
    if client is None:
        return _render_error('Unknown or unregistered OAuth client.', 400)
    redirect_uri = request.args.get('redirect_uri') or ''
    if redirect_uri not in _client_redirects(client):
        return _render_error('The redirect URI is not registered for this client.', 400)
    values, error, description = _validate_authorization(request.args, client)
    if error:
        return _authorization_error(redirect_uri, error, description, request.args.get('state'))
    session = _session()
    if session is None:
        return _login_redirect(request.full_path)
    context = {
        'client_name': client['client_name'],
        'redirect_uri': redirect_uri,
        'scopes': [(name, SCOPE_DESCRIPTIONS.get(name, name)) for name in values['scopes']],
        'csrf_token': session['csrf_token'],
        'hidden': _hidden_authorization_params({**values, 'client_id': client_id}),
        'owner_name': session['owner'],
    }
    return render_template('oauth_consent.html', **context)


@oauth_bp.route('/oauth/authorize', methods=['POST'])
def authorize_decision():
    if not oauth_enabled():
        return _render_error('Not found.', 404)
    if not owner_configured():
        return _render_error('The owner account is not configured yet.', 503)
    session = _session()
    if session is None:
        return _login_redirect('/account')
    client_id = request.form.get('client_id') or ''
    client = _resolve_client(client_id)
    if client is None:
        return _render_error('Unknown or unregistered OAuth client.', 400)
    redirect_uri = request.form.get('redirect_uri') or ''
    if redirect_uri not in _client_redirects(client):
        return _render_error('The redirect URI is not registered for this client.', 400)
    submitted_csrf = request.form.get('csrf_token') or ''
    if not hmac.compare_digest(submitted_csrf, session['csrf_token']):
        return _render_error('The consent form expired. Please try again.', 400)
    values, error, description = _validate_authorization(request.form, client)
    if error:
        return _authorization_error(redirect_uri, error, description, request.form.get('state'))
    if request.form.get('decision') != 'approve':
        return _authorization_error(redirect_uri, 'access_denied',
                                    'The owner denied the authorization request.',
                                    values['state'])
    store.upsert_consent(client_id, session['owner'], values['scopes'])
    code = store.create_authorization_code(
        client_id, redirect_uri, values['code_challenge'], values['scopes'],
        values['resource'], session['owner'], new_family_id())
    params = {'code': code}
    if values['state']:
        params['state'] = values['state']
    return _authorization_redirect(redirect_uri, params)


@oauth_bp.route('/oauth/token', methods=['POST'])
def token():
    if not oauth_enabled():
        return _json({'error': 'not_found'}, 404)
    if request.mimetype not in ('application/x-www-form-urlencoded', 'multipart/form-data'):
        return _oauth_error('invalid_request',
                            'The token endpoint requires application/x-www-form-urlencoded.')
    client, error, description = _authenticate_client()
    if error:
        headers = {}
        if request.headers.get('Authorization', '').startswith('Basic '):
            headers['WWW-Authenticate'] = 'Basic realm="AlienXFile OAuth"'
        return _oauth_error(error, description, 401, headers)
    grant_type = request.form.get('grant_type') or ''
    client_grants = store.client_public(client)['grant_types']
    if grant_type not in client_grants:
        return _oauth_error('unauthorized_client', 'The client may not use this grant type.')
    if grant_type == 'authorization_code':
        return _token_authorization_code(client)
    if grant_type == 'refresh_token':
        return _token_refresh(client)
    return _oauth_error('unsupported_grant_type', 'Unsupported grant_type.')


def _token_scope_response(values, client, refresh_token, refresh_ttl, access_token, access_ttl):
    response = {
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': access_ttl,
        'scope': scope_string(values['scopes']),
        'resource': values['resource'],
    }
    if refresh_token:
        response['refresh_token'] = refresh_token
        response['refresh_expires_in'] = refresh_ttl
    return _json(response, 200)


def _token_authorization_code(client):
    code = request.form.get('code') or ''
    redirect_uri = request.form.get('redirect_uri') or ''
    verifier = request.form.get('code_verifier') or ''
    row = store.get_authorization_code(code)
    if row is None or row['client_id'] != client['client_id']:
        return _oauth_error('invalid_grant', 'The authorization code is invalid or expired.')
    if row['redirect_uri'] != redirect_uri:
        return _oauth_error('invalid_grant', 'redirect_uri does not match the authorization request.')
    resource = request.form.get('resource') or row['resource']
    if resource != row['resource'] or resource != audience():
        return _oauth_error('invalid_target', 'The resource does not match this MCP endpoint.')
    if row['code_challenge_method'] != 'S256' or not verify_pkce(verifier, row['code_challenge']):
        return _oauth_error('invalid_grant', 'PKCE verification failed.')
    if row['expires_at'] <= time.time():
        return _oauth_error('invalid_grant', 'The authorization code is invalid or expired.')
    if row['consumed_at'] is not None:
        store.revoke_family(row['family_id'])
        return _oauth_error('invalid_grant', 'The authorization code has already been used.')
    if not store.consume_authorization_code(code):
        store.revoke_family(row['family_id'])
        return _oauth_error('invalid_grant', 'The authorization code is invalid or expired.')
    if store.get_consent(row['client_id'], row['owner']) is None:
        return _oauth_error('invalid_grant', 'The owner has revoked this client.')
    scopes = json.loads(row['scopes'])
    access, access_ttl = store.create_access_token(
        row['client_id'], scopes, row['resource'], row['owner'], row['family_id'])
    refresh = refresh_ttl = None
    if 'refresh_token' in store.client_public(client)['grant_types']:
        refresh, refresh_ttl = store.create_refresh_token(
            row['client_id'], scopes, row['resource'], row['owner'], row['family_id'])
    return _token_scope_response(
        {'scopes': scopes, 'resource': row['resource']}, client,
        refresh, refresh_ttl, access, access_ttl)


def _token_refresh(client):
    token_value = request.form.get('refresh_token') or ''
    row = store.get_refresh_token(token_value)
    if row is None or row['client_id'] != client['client_id']:
        return _oauth_error('invalid_grant', 'The refresh token is invalid or expired.')
    if row['revoked_at'] is not None or row['replaced_by'] is not None:
        store.revoke_family(row['family_id'])
        return _oauth_error('invalid_grant', 'The refresh token has already been used.')
    if row['expires_at'] <= time.time():
        return _oauth_error('invalid_grant', 'The refresh token is invalid or expired.')
    resource = request.form.get('resource') or row['resource']
    if resource != row['resource'] or resource != audience():
        return _oauth_error('invalid_target', 'The resource does not match this MCP endpoint.')
    original = json.loads(row['scopes'])
    requested = request.form.get('scope')
    if requested:
        try:
            scopes = parse_scope(requested, default=())
        except ValueError as exc:
            return _oauth_error('invalid_scope', str(exc))
        if not set(scopes).issubset(original):
            return _oauth_error('invalid_scope', 'Requested scopes exceed the original grant.')
    else:
        scopes = original
    if store.get_consent(row['client_id'], row['owner']) is None:
        return _oauth_error('invalid_grant', 'The owner has revoked this client.')
    rotated = store.rotate_refresh_token(row, scopes)
    if rotated is None:
        store.revoke_family(row['family_id'])
        return _oauth_error('invalid_grant', 'The refresh token has already been used.')
    new_refresh, refresh_ttl = rotated
    access, access_ttl = store.create_access_token(
        row['client_id'], scopes, row['resource'], row['owner'], row['family_id'])
    return _token_scope_response(
        {'scopes': scopes, 'resource': row['resource']}, client,
        new_refresh, refresh_ttl, access, access_ttl)


@oauth_bp.route('/oauth/revoke', methods=['POST'])
def revoke():
    if not oauth_enabled():
        return _json({'error': 'not_found'}, 404)
    client, error, description = _authenticate_client()
    if error:
        headers = {}
        if request.headers.get('Authorization', '').startswith('Basic '):
            headers['WWW-Authenticate'] = 'Basic realm="AlienXFile OAuth"'
        return _oauth_error(error, description, 401, headers)
    token_value = request.form.get('token') or ''
    if not token_value:
        return _oauth_error('invalid_request', 'token is required.')
    store.revoke_token(token_value, client['client_id'])
    response = current_app.response_class('', status=200)
    return _no_store(response)


@oauth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if not oauth_enabled():
        return _render_error('Not found.', 404)
    if not owner_configured():
        return _render_error('The owner account is not configured yet.', 503)
    next_url = safe_next_path(request.values.get('next') or '/account')
    if request.method == 'GET':
        if _session() is not None:
            return redirect(next_url, code=303)
        return _login_form(next_url)
    secret = current_app.config['SECRET_KEY']
    submitted = request.form.get('csrf_token') or ''
    cookie = request.cookies.get(LOGIN_CSRF_COOKIE) or ''
    if not csrf_verify(submitted, cookie, secret):
        return _login_form(next_url, 'The sign-in form expired. Please try again.', 400)
    username = (request.form.get('username') or '').strip()[:200]
    password = request.form.get('password') or ''
    retry = store.record_rate_limit(
        'login_user', username or 'unknown', 10,
        int(current_app.config.get('OAUTH_LOGIN_WINDOW', 900)))
    if retry:
        response, _ = _render_error(
            f'Too many sign-in attempts. Try again in {retry} seconds.', 429)
        response.headers['Retry-After'] = str(retry)
        return response
    if not verify_owner_password(
            username, password,
            current_app.config['OWNER_USERNAME'],
            current_app.config['OWNER_PASSWORD_HASH']):
        return _login_form(next_url, 'Invalid username or password.', 401)
    previous_session = _session_token()
    if previous_session:
        store.revoke_session(previous_session)
    token, _csrf, ttl = store.create_session(current_app.config['OWNER_USERNAME'])
    response = redirect(next_url, code=303)
    _set_session_cookie(response, token, ttl)
    response.delete_cookie(LOGIN_CSRF_COOKIE, path='/login')
    return response


def _login_form(next_url, error=None, status=200):
    csrf = csrf_issue(current_app.config['SECRET_KEY'])
    response = current_app.make_response(
        render_template('oauth_login.html', csrf_token=csrf, next_url=next_url,
                        error=error, owner_name=current_app.config['OWNER_USERNAME']))
    response.status_code = status
    response.set_cookie(LOGIN_CSRF_COOKIE, csrf, max_age=900, httponly=True,
                        secure=bool(current_app.config.get('OAUTH_COOKIE_SECURE')),
                        samesite='Lax', path='/login')
    return response


@oauth_bp.route('/logout', methods=['POST'])
def logout():
    session = _session()
    if session is not None:
        submitted = request.form.get('csrf_token') or ''
        if not hmac.compare_digest(submitted, session['csrf_token']):
            return _render_error('The sign-out form expired. Please try again.', 400)
        store.revoke_session(_session_token())
    response = redirect('/login', code=303)
    return _clear_session_cookie(response)


@oauth_bp.route('/account', methods=['GET'])
def account():
    session = _session()
    if session is None:
        return _login_redirect('/account')
    clients = store.list_consents(session['owner'])
    return render_template('account.html', clients=clients, csrf_token=session['csrf_token'],
                           owner_name=session['owner'], issuer=issuer())


def _revoke_client(client_id):
    session = _session()
    if session is None:
        return _login_redirect('/account')
    submitted = request.form.get('csrf_token') or ''
    if not hmac.compare_digest(submitted, session['csrf_token']):
        return _render_error('The revocation form expired. Please try again.', 400)
    if client_id and store.get_client(client_id) is not None:
        store.revoke_client(client_id, session['owner'])
    return redirect('/account', code=303)


@oauth_bp.route('/account/revoke-client', methods=['POST'])
def revoke_client_form():
    return _revoke_client(request.form.get('client_id') or '')


@oauth_bp.route('/account/clients/<path:client_id>/revoke', methods=['POST'])
def revoke_client(client_id):
    return _revoke_client(client_id)


@oauth_bp.after_request
def oauth_response_headers(response):
    if request.endpoint in CORS_ENDPOINTS:
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Vary'] = 'Origin'
    return response
