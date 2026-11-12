SUPPORTED_SCOPES = (
    'alienxfile:read',
    'alienxfile:write',
    'alienxfile:delete',
    'alienxfile:admin',
)
DEFAULT_SCOPES = ('alienxfile:read', 'alienxfile:write')
READ_SCOPE = 'alienxfile:read'
WRITE_SCOPE = 'alienxfile:write'
DELETE_SCOPE = 'alienxfile:delete'
ADMIN_SCOPE = 'alienxfile:admin'

SCOPE_DESCRIPTIONS = {
    READ_SCOPE: 'Read shares and check share status',
    WRITE_SCOPE: 'Create text and file shares',
    DELETE_SCOPE: 'Delete shares created through this connection',
    ADMIN_SCOPE: 'Manage account-level authorization settings',
}

OAUTH_SCHEMA = '''
    CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret_hash TEXT,
        client_name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        grant_types TEXT NOT NULL,
        response_types TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL,
        scope TEXT,
        source TEXT NOT NULL DEFAULT 'dcr',
        metadata TEXT,
        created_at DOUBLE PRECISION NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS oauth_clients_updated ON oauth_clients(updated_at);
    CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        code_challenge_method TEXT NOT NULL,
        scopes TEXT NOT NULL,
        resource TEXT NOT NULL,
        owner TEXT NOT NULL,
        family_id TEXT NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        consumed_at DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS oauth_codes_expiry ON oauth_authorization_codes(expires_at);
    CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        scopes TEXT NOT NULL,
        resource TEXT NOT NULL,
        owner TEXT NOT NULL,
        family_id TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        revoked_at DOUBLE PRECISION,
        replaced_by TEXT
    );
    CREATE INDEX IF NOT EXISTS oauth_refresh_expiry ON oauth_refresh_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS oauth_refresh_family ON oauth_refresh_tokens(family_id);
    CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        scopes TEXT NOT NULL,
        resource TEXT NOT NULL,
        owner TEXT NOT NULL,
        family_id TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        revoked_at DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS oauth_access_expiry ON oauth_access_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS oauth_access_family ON oauth_access_tokens(family_id);
    CREATE TABLE IF NOT EXISTS oauth_sessions (
        session_id_hash TEXT PRIMARY KEY,
        csrf_token TEXT NOT NULL,
        owner TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        revoked_at DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS oauth_sessions_expiry ON oauth_sessions(expires_at);
    CREATE TABLE IF NOT EXISTS oauth_consents (
        client_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        granted_scopes TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL,
        revoked_at DOUBLE PRECISION,
        PRIMARY KEY (client_id, owner)
    );
    CREATE INDEX IF NOT EXISTS oauth_consents_owner ON oauth_consents(owner);
'''
