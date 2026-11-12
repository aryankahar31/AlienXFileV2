from flask import current_app

from .constants import SUPPORTED_SCOPES


def oauth_enabled():
    return bool(current_app.config.get('OAUTH_ENABLED'))


def owner_configured():
    return bool(current_app.config.get('OAUTH_OWNER_CONFIGURED'))


def issuer():
    return (current_app.config.get('OAUTH_ISSUER') or '').rstrip('/')


def audience():
    return current_app.config.get('OAUTH_AUDIENCE') or (issuer() + '/mcp')


def protected_resource_url():
    return issuer() + '/.well-known/oauth-protected-resource'


def authorization_server_metadata():
    base = issuer()
    methods = ['none', 'client_secret_basic', 'client_secret_post']
    data = {
        'issuer': base,
        'authorization_endpoint': base + '/oauth/authorize',
        'token_endpoint': base + '/oauth/token',
        'revocation_endpoint': base + '/oauth/revoke',
        'response_types_supported': ['code'],
        'response_modes_supported': ['query'],
        'grant_types_supported': ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported': ['S256'],
        'token_endpoint_auth_methods_supported': methods,
        'revocation_endpoint_auth_methods_supported': methods,
        'scopes_supported': list(SUPPORTED_SCOPES),
        'authorization_response_iss_parameter_supported': True,
        'client_id_metadata_document_supported': bool(
            current_app.config.get('OAUTH_CIMD_ENABLED', True)),
    }
    if current_app.config.get('OAUTH_DCR_ENABLED', True):
        data['registration_endpoint'] = base + '/oauth/register'
    return data


def protected_resource_metadata():
    base = issuer()
    return {
        'resource': audience(),
        'authorization_servers': [base],
        'scopes_supported': list(SUPPORTED_SCOPES),
        'bearer_methods_supported': ['header'],
        'resource_name': 'AlienXFile MCP',
        'resource_documentation': base + '/support',
        'resource_policy_uri': base + '/privacy',
        'resource_tos_uri': base + '/terms',
    }


def challenge_header(scope=None, error=None, description=None):
    parts = [f'resource_metadata="{protected_resource_url()}"']
    if error:
        parts.append(f'error="{error}"')
    if description:
        safe = str(description).replace('"', "'")[:200]
        parts.append(f'error_description="{safe}"')
    if scope:
        if isinstance(scope, (list, tuple, set)):
            scope = ' '.join(sorted(scope))
        parts.append(f'scope="{scope}"')
    return 'Bearer ' + ', '.join(parts)
