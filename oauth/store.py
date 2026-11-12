import json
import secrets
import time

from flask import current_app

from .constants import SUPPORTED_SCOPES
from .security import hash_token, new_csrf_token, new_session_token


def _fa():
    import flask_app
    return flask_app


def _now():
    return time.time()


def _dict(row):
    return dict(row) if row is not None else None


def _json_list(value):
    try:
        parsed = json.loads(value or '[]')
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _prune(db, now):
    fa = _fa()
    fa.query(db, 'DELETE FROM oauth_authorization_codes WHERE expires_at <= ?', (now - 86400,))
    fa.query(db, 'DELETE FROM oauth_access_tokens WHERE expires_at <= ?', (now,))
    fa.query(db, 'DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?', (now,))
    fa.query(db, 'DELETE FROM oauth_sessions WHERE expires_at <= ?', (now,))
    fa.query(db, '''DELETE FROM oauth_clients
                    WHERE source IN (?, ?) AND updated_at <= ?
                      AND client_id NOT IN (SELECT client_id FROM oauth_consents)''',
             ('dcr', 'cimd', now - 90 * 86400))


def client_public(row):
    data = _dict(row)
    if data is None:
        return None
    return {
        'client_id': data['client_id'],
        'client_name': data['client_name'],
        'redirect_uris': _json_list(data['redirect_uris']),
        'grant_types': _json_list(data['grant_types']),
        'response_types': _json_list(data['response_types']),
        'token_endpoint_auth_method': data['token_endpoint_auth_method'],
        'scope': data.get('scope') or '',
        'source': data.get('source') or 'dcr',
        'created_at': data['created_at'],
        'updated_at': data['updated_at'],
    }


def get_client(client_id):
    db = _fa().get_db()
    row = _fa().query(db, 'SELECT * FROM oauth_clients WHERE client_id = ?', (client_id,)).fetchone()
    return _dict(row)


def list_clients():
    db = _fa().get_db()
    rows = _fa().query(db, 'SELECT * FROM oauth_clients ORDER BY updated_at DESC').fetchall()
    return [_dict(row) for row in rows]


def upsert_client(client_id, client_name, redirect_uris, grant_types, response_types,
                  token_endpoint_auth_method, scope, source, metadata,
                  client_secret_hash):
    fa = _fa()
    db = fa.get_db()
    now = _now()
    with fa.transaction(db):
        fa.query(db, '''INSERT INTO oauth_clients
                        (client_id, client_secret_hash, client_name, redirect_uris, grant_types,
                         response_types, token_endpoint_auth_method, scope, source, metadata,
                         created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(client_id) DO UPDATE SET
                          client_secret_hash = excluded.client_secret_hash,
                          client_name = excluded.client_name,
                          redirect_uris = excluded.redirect_uris,
                          grant_types = excluded.grant_types,
                          response_types = excluded.response_types,
                          token_endpoint_auth_method = excluded.token_endpoint_auth_method,
                          scope = excluded.scope,
                          source = excluded.source,
                          metadata = excluded.metadata,
                          updated_at = excluded.updated_at''',
                 (client_id, client_secret_hash, client_name, json.dumps(redirect_uris),
                  json.dumps(grant_types), json.dumps(response_types),
                  token_endpoint_auth_method, scope, source,
                  json.dumps(metadata, sort_keys=True), now, now))
    return get_client(client_id)


def touch_client(client_id):
    fa = _fa()
    db = fa.get_db()
    with fa.transaction(db):
        fa.query(db, 'UPDATE oauth_clients SET updated_at = ? WHERE client_id = ?',
                 (_now(), client_id))


def get_consent(client_id, owner):
    db = _fa().get_db()
    row = _fa().query(db, '''SELECT * FROM oauth_consents
                             WHERE client_id = ? AND owner = ? AND revoked_at IS NULL''',
                      (client_id, owner)).fetchone()
    return _dict(row)


def upsert_consent(client_id, owner, scopes):
    fa = _fa()
    db = fa.get_db()
    now = _now()
    with fa.transaction(db):
        fa.query(db, '''INSERT INTO oauth_consents
                        (client_id, owner, granted_scopes, created_at, updated_at, revoked_at)
                        VALUES (?, ?, ?, ?, ?, NULL)
                        ON CONFLICT(client_id, owner) DO UPDATE SET
                          granted_scopes = excluded.granted_scopes,
                          updated_at = excluded.updated_at,
                          revoked_at = NULL''',
                 (client_id, owner, json.dumps(scopes), now, now))


def list_consents(owner):
    db = _fa().get_db()
    rows = _fa().query(db, '''SELECT c.client_id, c.client_name, c.source, c.updated_at,
                                     ct.granted_scopes, ct.created_at AS consent_created_at,
                                     ct.updated_at AS consent_updated_at
                              FROM oauth_consents ct
                              JOIN oauth_clients c ON c.client_id = ct.client_id
                              WHERE ct.owner = ? AND ct.revoked_at IS NULL
                              ORDER BY ct.updated_at DESC''', (owner,)).fetchall()
    result = []
    for row in rows:
        item = _dict(row)
        item['granted_scopes'] = _json_list(item['granted_scopes'])
        result.append(item)
    return result


def create_session(owner):
    fa = _fa()
    db = fa.get_db()
    token = new_session_token()
    csrf = new_csrf_token()
    now = _now()
    ttl = int(current_app.config.get('OAUTH_SESSION_TTL', 43200))
    with fa.transaction(db):
        _prune(db, now)
        fa.query(db, '''INSERT INTO oauth_sessions
                        (session_id_hash, csrf_token, owner, created_at, expires_at, revoked_at)
                        VALUES (?, ?, ?, ?, ?, NULL)''',
                 (hash_token(token), csrf, owner, now, now + ttl))
    return token, csrf, ttl


def get_session(token):
    if not token:
        return None
    db = _fa().get_db()
    row = _fa().query(db, '''SELECT * FROM oauth_sessions
                             WHERE session_id_hash = ? AND revoked_at IS NULL AND expires_at > ?''',
                      (hash_token(token), _now())).fetchone()
    return _dict(row)


def revoke_session(token):
    if not token:
        return
    fa = _fa()
    db = fa.get_db()
    with fa.transaction(db):
        fa.query(db, '''UPDATE oauth_sessions SET revoked_at = ?
                        WHERE session_id_hash = ? AND revoked_at IS NULL''',
                 (_now(), hash_token(token)))


def create_authorization_code(client_id, redirect_uri, code_challenge, scopes, resource,
                              owner, family_id):
    fa = _fa()
    db = fa.get_db()
    code = secrets.token_urlsafe(32)
    now = _now()
    ttl = int(current_app.config.get('OAUTH_CODE_TTL', 300))
    with fa.transaction(db):
        _prune(db, now)
        fa.query(db, '''INSERT INTO oauth_authorization_codes
                        (code_hash, client_id, redirect_uri, code_challenge, code_challenge_method,
                         scopes, resource, owner, family_id, expires_at, consumed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)''',
                 (hash_token(code), client_id, redirect_uri, code_challenge, 'S256',
                  json.dumps(scopes), resource, owner, family_id, now + ttl))
    return code


def get_authorization_code(code):
    if not code:
        return None
    db = _fa().get_db()
    row = _fa().query(db, 'SELECT * FROM oauth_authorization_codes WHERE code_hash = ?',
                      (hash_token(code),)).fetchone()
    return _dict(row)


def consume_authorization_code(code):
    fa = _fa()
    db = fa.get_db()
    now = _now()
    with fa.transaction(db):
        updated = fa.query(db, '''UPDATE oauth_authorization_codes SET consumed_at = ?
                                  WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?''',
                           (now, hash_token(code), now))
        return getattr(updated, 'rowcount', 0) == 1


def create_access_token(client_id, scopes, resource, owner, family_id):
    fa = _fa()
    db = fa.get_db()
    token = secrets.token_urlsafe(32)
    now = _now()
    ttl = int(current_app.config.get('OAUTH_ACCESS_TOKEN_TTL', 900))
    with fa.transaction(db):
        fa.query(db, '''INSERT INTO oauth_access_tokens
                        (token_hash, client_id, scopes, resource, owner, family_id,
                         created_at, expires_at, revoked_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)''',
                 (hash_token(token), client_id, json.dumps(scopes), resource, owner,
                  family_id, now, now + ttl))
    return token, ttl


def create_refresh_token(client_id, scopes, resource, owner, family_id):
    fa = _fa()
    db = fa.get_db()
    token = secrets.token_urlsafe(48)
    now = _now()
    ttl = int(current_app.config.get('OAUTH_REFRESH_TOKEN_TTL', 2592000))
    with fa.transaction(db):
        fa.query(db, '''INSERT INTO oauth_refresh_tokens
                        (token_hash, client_id, scopes, resource, owner, family_id,
                         created_at, expires_at, revoked_at, replaced_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)''',
                 (hash_token(token), client_id, json.dumps(scopes), resource, owner,
                  family_id, now, now + ttl))
    return token, ttl


def get_refresh_token(token):
    if not token:
        return None
    db = _fa().get_db()
    row = _fa().query(db, 'SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?',
                      (hash_token(token),)).fetchone()
    return _dict(row)


def rotate_refresh_token(old_row, scopes):
    fa = _fa()
    db = fa.get_db()
    now = _now()
    new_refresh = secrets.token_urlsafe(48)
    ttl = int(current_app.config.get('OAUTH_REFRESH_TOKEN_TTL', 2592000))
    with fa.transaction(db):
        updated = fa.query(db, '''UPDATE oauth_refresh_tokens
                                  SET revoked_at = ?, replaced_by = ?
                                  WHERE token_hash = ? AND revoked_at IS NULL
                                    AND replaced_by IS NULL AND expires_at > ?''',
                           (now, hash_token(new_refresh), old_row['token_hash'], now))
        if getattr(updated, 'rowcount', 0) != 1:
            return None
        fa.query(db, '''INSERT INTO oauth_refresh_tokens
                        (token_hash, client_id, scopes, resource, owner, family_id,
                         created_at, expires_at, revoked_at, replaced_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)''',
                 (hash_token(new_refresh), old_row['client_id'], json.dumps(scopes),
                  old_row['resource'], old_row['owner'], old_row['family_id'],
                  now, now + ttl))
    return new_refresh, ttl


def get_access_token(token):
    if not token:
        return None
    db = _fa().get_db()
    row = _fa().query(db, 'SELECT * FROM oauth_access_tokens WHERE token_hash = ?',
                      (hash_token(token),)).fetchone()
    return _dict(row)


def validate_access_token(token, audience):
    row = get_access_token(token)
    if row is None:
        return None
    if row['expires_at'] <= _now() or row['revoked_at'] is not None:
        return None
    if row['resource'] != audience:
        return None
    try:
        scopes = json.loads(row['scopes'])
    except (TypeError, ValueError):
        return None
    if not isinstance(scopes, list) or not all(scope in SUPPORTED_SCOPES for scope in scopes):
        return None
    return {
        'kind': 'oauth',
        'client_id': row['client_id'],
        'owner': row['owner'],
        'scopes': scopes,
        'resource': row['resource'],
        'family_id': row['family_id'],
    }


def revoke_family(family_id):
    if not family_id:
        return
    fa = _fa()
    db = fa.get_db()
    now = _now()
    with fa.transaction(db):
        fa.query(db, '''UPDATE oauth_refresh_tokens SET revoked_at = ?
                        WHERE family_id = ? AND revoked_at IS NULL''', (now, family_id))
        fa.query(db, '''UPDATE oauth_access_tokens SET revoked_at = ?
                        WHERE family_id = ? AND revoked_at IS NULL''', (now, family_id))


def revoke_token(token, client_id):
    if not token:
        return
    fa = _fa()
    db = fa.get_db()
    now = _now()
    token_hash = hash_token(token)
    with fa.transaction(db):
        access = fa.query(db, '''SELECT * FROM oauth_access_tokens WHERE token_hash = ?''',
                          (token_hash,)).fetchone()
        if access is not None and access['client_id'] == client_id:
            fa.query(db, '''UPDATE oauth_access_tokens SET revoked_at = ?
                            WHERE family_id = ? AND revoked_at IS NULL''',
                     (now, access['family_id']))
            fa.query(db, '''UPDATE oauth_refresh_tokens SET revoked_at = ?
                            WHERE family_id = ? AND revoked_at IS NULL''',
                     (now, access['family_id']))
            return
        refresh = fa.query(db, '''SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?''',
                           (token_hash,)).fetchone()
        if refresh is not None and refresh['client_id'] == client_id:
            fa.query(db, '''UPDATE oauth_refresh_tokens SET revoked_at = ?
                            WHERE family_id = ? AND revoked_at IS NULL''',
                     (now, refresh['family_id']))
            fa.query(db, '''UPDATE oauth_access_tokens SET revoked_at = ?
                            WHERE family_id = ? AND revoked_at IS NULL''',
                     (now, refresh['family_id']))


def revoke_client(client_id, owner=None):
    fa = _fa()
    db = fa.get_db()
    now = _now()
    with fa.transaction(db):
        if owner is None:
            fa.query(db, '''UPDATE oauth_consents SET revoked_at = ?
                            WHERE client_id = ? AND revoked_at IS NULL''', (now, client_id))
        else:
            fa.query(db, '''UPDATE oauth_consents SET revoked_at = ?
                            WHERE client_id = ? AND owner = ? AND revoked_at IS NULL''',
                     (now, client_id, owner))
        fa.query(db, '''UPDATE oauth_refresh_tokens SET revoked_at = ?
                        WHERE client_id = ? AND revoked_at IS NULL''', (now, client_id))
        fa.query(db, '''UPDATE oauth_access_tokens SET revoked_at = ?
                        WHERE client_id = ? AND revoked_at IS NULL''', (now, client_id))
        fa.query(db, '''UPDATE oauth_authorization_codes SET consumed_at = ?
                        WHERE client_id = ? AND consumed_at IS NULL''', (now, client_id))


def record_rate_limit(action, identity, limit, window):
    fa = _fa()
    db = fa.get_db()
    now = _now()
    identity = str(identity or 'unknown')[:200]
    with fa.transaction(db):
        fa.query(db, 'DELETE FROM rate_limits WHERE action = ? AND started <= ?',
                 (action, now - window))
        fa.query(db, '''INSERT INTO rate_limits VALUES (?, ?, ?, 1)
                        ON CONFLICT(ip, action) DO UPDATE SET hits = rate_limits.hits + 1''',
                 (identity, action, now))
        row = fa.query(db, 'SELECT hits, started FROM rate_limits WHERE ip = ? AND action = ?',
                       (identity, action)).fetchone()
    if row['hits'] > limit:
        return max(1, int(row['started'] + window - now) + 1)
    return None
