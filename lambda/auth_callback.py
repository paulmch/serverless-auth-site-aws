import html
import json
import os
import time
import uuid
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any

import boto3
from jose import jwt

from oauth_state import OAUTH_STATE_COOKIE, parse_state
from security_headers import HTML_CONTENT_SECURITY_POLICY, get_security_headers


# DynamoDB client (initialized once for connection reuse)
dynamodb = boto3.resource('dynamodb')


def exchange_code_for_tokens(code: str, redirect_uri: str) -> Dict[str, Any]:
    """Exchange authorization code for tokens with Cognito."""
    cognito_domain = os.environ.get('COGNITO_DOMAIN')
    client_id = os.environ.get('COGNITO_CLIENT_ID')
    region = os.environ.get('AWS_REGION', 'us-east-1')

    if not cognito_domain or not client_id:
        raise ValueError("Missing required environment variables")

    # Build token endpoint URL
    token_url = f"https://{cognito_domain}.auth.{region}.amazoncognito.com/oauth2/token"

    # Prepare request data
    data = urllib.parse.urlencode({
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'code': code,
        'redirect_uri': redirect_uri
    }).encode('utf-8')

    # Make request
    req = urllib.request.Request(
        token_url,
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"Token exchange failed: {e.code} - {error_body}")
        raise


def store_session(session_id: str, tokens: Dict[str, str], user_info: Dict[str, str]) -> None:
    """Store session with tokens in DynamoDB."""
    table_name = os.environ.get('USER_SESSIONS_TABLE')
    if not table_name:
        raise ValueError("USER_SESSIONS_TABLE environment variable not set")

    table = dynamodb.Table(table_name)
    current_time = int(time.time())

    # Session expires in 30 days (matches refresh token lifetime)
    session_ttl = 30 * 24 * 3600

    item = {
        'sessionId': session_id,
        'userId': user_info.get('sub', 'unknown'),
        'email': user_info.get('email', 'unknown'),
        'username': user_info.get('cognito:username', user_info.get('email', 'unknown')),
        'idToken': tokens['id_token'],
        'accessToken': tokens['access_token'],
        'refreshToken': tokens.get('refresh_token', ''),
        'createdAt': current_time,
        'lastAccessedAt': current_time,
        'expiresAt': current_time + session_ttl,  # TTL for DynamoDB auto-cleanup
    }

    table.put_item(Item=item)
    print(f"Session stored for user: {user_info.get('email', 'unknown')}")


def get_cookie(event: Dict[str, Any], name: str) -> str:
    """Read a single cookie value from the request headers."""
    headers = event.get('headers') or {}
    cookie_header = headers.get('Cookie') or headers.get('cookie') or ''

    for cookie in cookie_header.split(';'):
        cookie = cookie.strip()
        if cookie.startswith(f'{name}='):
            return urllib.parse.unquote(cookie.split('=', 1)[1])

    return ''


def error_page(status_code: int, title: str, message: str) -> Dict[str, Any]:
    """Render a minimal HTML error page."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8',
            **get_security_headers(HTML_CONTENT_SECURITY_POLICY)
        },
        'body': f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>{html.escape(title)}</title>
</head>
<body>
    <h1>{html.escape(title)}</h1>
    <p>{message}</p>
    <p><a href="/">Return to Home</a></p>
</body>
</html>"""
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle OAuth2 callback from Cognito."""
    # Never log the raw event. It carries the OAuth authorization code in the
    # query string, which is redeemable for this user's tokens by anyone who can
    # read the log group.
    print("Auth callback invoked")

    try:
        # Extract query parameters
        query_params = event.get('queryStringParameters') or {}
        code = query_params.get('code')
        error = query_params.get('error')

        # Handle errors from Cognito
        if error:
            error_description = query_params.get('error_description', 'Unknown error')
            # Escape before interpolating: both values come straight from the
            # query string, so an attacker controls them.
            return error_page(
                400,
                'Authentication Error',
                f'{html.escape(error)}: {html.escape(error_description)}',
            )

        # Validate code parameter
        if not code:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'text/plain; charset=utf-8',
                    **get_security_headers()
                },
                'body': 'Missing authorization code'
            }

        # Verify the OAuth state before spending the authorization code. The
        # nonce must match the one the decider set in an HttpOnly cookie when it
        # started this login, which is what prevents an attacker from completing
        # a flow in someone else's browser using their own code.
        state_valid, post_login_path = parse_state(
            query_params.get('state', ''),
            get_cookie(event, OAUTH_STATE_COOKIE),
        )

        if not state_valid:
            print("OAuth state validation failed - rejecting callback")
            return error_page(
                400,
                'Authentication Error',
                'This sign-in link is invalid or has expired. Please start again.',
            )

        # Build redirect URI (must match what was registered with Cognito)
        host = event['headers'].get('Host', 'localhost')
        stage = event.get('requestContext', {}).get('stage', '')

        # Handle API Gateway stage in path
        base_path = f"/{stage}" if stage and stage != '$default' else ''
        redirect_uri = f"https://{host}{base_path}/auth/callback"

        print(f"Using redirect URI: {redirect_uri}")

        # Exchange code for tokens
        try:
            token_response = exchange_code_for_tokens(code, redirect_uri)
            print("Successfully exchanged code for tokens")

            # Extract tokens
            id_token = token_response.get('id_token')
            access_token = token_response.get('access_token')
            refresh_token = token_response.get('refresh_token')

            if not id_token or not access_token:
                raise ValueError("Missing tokens in response")

            # Decode id_token to get user info (no verification needed - Cognito just issued it)
            user_info = jwt.get_unverified_claims(id_token)

            # Generate unique session ID
            session_id = str(uuid.uuid4())

            # Store tokens in DynamoDB (server-side, never exposed to browser)
            store_session(session_id, {
                'id_token': id_token,
                'access_token': access_token,
                'refresh_token': refresh_token or ''
            }, user_info)

            # Set only session_id cookie (HttpOnly - not accessible to JavaScript)
            # This is the ONLY cookie sent to the browser - tokens stay server-side
            cookie_path = base_path or '/'
            session_ttl = 30 * 24 * 3600  # 30 days
            session_cookie = f"session_id={session_id}; HttpOnly; Secure; SameSite=Lax; Path={cookie_path}; Max-Age={session_ttl}"

            # The state nonce is single-use; expire it now that it has been spent.
            clear_state_cookie = (
                f"{OAUTH_STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; "
                f"Path={cookie_path}; Max-Age=0"
            )

            # Return the user to wherever they were headed before logging in.
            # post_login_path came out of the signed-off state and is already
            # constrained to a same-origin path.
            redirect_location = f"{base_path}{post_login_path}" if base_path else post_login_path

            return {
                'statusCode': 302,
                'multiValueHeaders': {
                    'Set-Cookie': [session_cookie, clear_state_cookie]
                },
                'headers': {
                    'Location': redirect_location,
                    **get_security_headers()
                },
                'body': ''
            }

        except Exception as e:
            print(f"Token exchange error: {str(e)}")
            return error_page(
                500,
                'Authentication Failed',
                'Unable to complete the authentication process.',
            )

    except Exception as e:
        print(f"Auth callback error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'text/plain; charset=utf-8',
                **get_security_headers()
            },
            'body': 'Internal server error'
        }
