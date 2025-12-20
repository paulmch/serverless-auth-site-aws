import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

import boto3
from jose import jwt


# DynamoDB client (initialized once for connection reuse)
dynamodb = boto3.resource('dynamodb')


def refresh_tokens(refresh_token: str) -> Dict[str, Any]:
    """Exchange refresh token for new access and id tokens with Cognito."""
    cognito_domain = os.environ.get('COGNITO_DOMAIN')
    client_id = os.environ.get('COGNITO_CLIENT_ID')
    region = os.environ.get('AWS_REGION', 'us-east-1')

    if not cognito_domain or not client_id:
        raise ValueError("Missing required environment variables")

    # Build token endpoint URL
    token_url = f"https://{cognito_domain}.auth.{region}.amazoncognito.com/oauth2/token"

    # Prepare request data for refresh token grant
    data = urllib.parse.urlencode({
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'refresh_token': refresh_token
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
        print(f"Token refresh failed: {e.code} - {error_body}")
        raise


def extract_session_id_from_cookies(cookie_header: str) -> Optional[str]:
    """Extract session_id from cookie header."""
    if not cookie_header:
        return None

    cookies = {}
    for cookie in cookie_header.split(';'):
        if '=' in cookie:
            name, value = cookie.strip().split('=', 1)
            cookies[name] = value

    if 'session_id' in cookies:
        return urllib.parse.unquote(cookies['session_id'])

    return None


def get_session_from_dynamodb(session_id: str) -> Optional[Dict[str, Any]]:
    """Look up session by session_id from DynamoDB."""
    table_name = os.environ.get('USER_SESSIONS_TABLE')
    if not table_name:
        print("USER_SESSIONS_TABLE environment variable not set")
        return None

    try:
        table = dynamodb.Table(table_name)
        response = table.get_item(Key={'sessionId': session_id})

        if 'Item' not in response:
            print(f"Session not found: {session_id[:8]}...")
            return None

        return response['Item']

    except Exception as e:
        print(f"DynamoDB lookup failed: {str(e)}")
        return None


def update_session_tokens(session_id: str, tokens: Dict[str, str]) -> bool:
    """Update tokens in existing session."""
    table_name = os.environ.get('USER_SESSIONS_TABLE')
    if not table_name:
        return False

    try:
        table = dynamodb.Table(table_name)
        current_time = int(time.time())

        # Decode new id_token to get updated user info
        user_info = jwt.get_unverified_claims(tokens['id_token'])

        update_expression = 'SET idToken = :id, accessToken = :access, lastAccessedAt = :time, email = :email'
        expression_values = {
            ':id': tokens['id_token'],
            ':access': tokens['access_token'],
            ':time': current_time,
            ':email': user_info.get('email', 'unknown')
        }

        # Update refresh token if a new one was provided (token rotation)
        if tokens.get('refresh_token'):
            update_expression += ', refreshToken = :refresh'
            expression_values[':refresh'] = tokens['refresh_token']

        table.update_item(
            Key={'sessionId': session_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )

        print(f"Session tokens updated: {session_id[:8]}...")
        return True

    except Exception as e:
        print(f"Failed to update session tokens: {str(e)}")
        return False


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Decider Lambda: Attempts to refresh tokens or redirects to Cognito login."""
    print(f"Auth decider event: {json.dumps({k: v for k, v in event.items() if k != 'headers'})}")

    try:
        # Extract query parameters for redirect URL
        query_params = event.get('queryStringParameters') or {}
        redirect_to = query_params.get('redirect_to', '/')

        # Get request context for building URLs
        host = event['headers'].get('Host', 'localhost')
        stage = event.get('requestContext', {}).get('stage', '')
        base_path = f"/{stage}" if stage and stage != '$default' else ''

        # Extract session_id from cookies
        headers = event.get('headers', {})
        cookie_header = headers.get('Cookie', '')
        session_id = extract_session_id_from_cookies(cookie_header)

        print(f"Host: {host}")
        print(f"Stage: {stage}")
        print(f"Base path: {base_path}")
        print(f"Redirect target: {redirect_to}")
        print(f"Session ID present: {bool(session_id)}")

        # Log cookie details for debugging
        if cookie_header:
            cookies = {}
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    name, _ = cookie.strip().split('=', 1)
                    cookies[name] = '***'  # Don't log actual values
            print(f"Available cookies: {list(cookies.keys())}")

        if session_id:
            # Look up session from DynamoDB
            session = get_session_from_dynamodb(session_id)

            if session and session.get('refreshToken'):
                # Attempt to refresh tokens
                try:
                    token_response = refresh_tokens(session['refreshToken'])
                    print("Successfully refreshed tokens with Cognito")

                    # Extract new tokens
                    id_token = token_response.get('id_token')
                    access_token = token_response.get('access_token')
                    new_refresh_token = token_response.get('refresh_token')  # May be None

                    if not id_token or not access_token:
                        raise ValueError("Missing tokens in refresh response")

                    # Update tokens in DynamoDB (session_id stays the same)
                    update_success = update_session_tokens(session_id, {
                        'id_token': id_token,
                        'access_token': access_token,
                        'refresh_token': new_refresh_token or ''
                    })

                    if not update_success:
                        print("Warning: Failed to update session in DynamoDB")
                        # Continue anyway - the tokens are valid

                    # Build redirect URL, avoiding double slashes
                    if redirect_to == '/' and base_path:
                        redirect_url = base_path
                    elif redirect_to.startswith('/') and base_path:
                        redirect_url = base_path + redirect_to
                    else:
                        redirect_url = f"{base_path}{redirect_to}"

                    # Redirect back to original destination
                    # No cookies to set - session_id cookie is still valid
                    return {
                        'statusCode': 302,
                        'headers': {
                            'Location': redirect_url,
                            'Cache-Control': 'no-cache, no-store, must-revalidate'
                        },
                        'body': ''
                    }

                except Exception as e:
                    print(f"Token refresh failed: {str(e)}")
                    # Continue to login redirect below
            else:
                print("No valid session or refresh token found")

        # No session, no refresh token, or refresh failed - redirect to Cognito login
        print("Redirecting to Cognito login")

        # Build Cognito login URL
        cognito_domain = os.environ.get('COGNITO_DOMAIN')
        client_id = os.environ.get('COGNITO_CLIENT_ID')
        region = os.environ.get('AWS_REGION', 'us-east-1')

        if not cognito_domain or not client_id:
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'text/html',
                    'Cache-Control': 'no-cache, no-store, must-revalidate'
                },
                'body': """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Configuration Error</title>
                        <style>
                            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                            .error { color: #d32f2f; }
                        </style>
                    </head>
                    <body>
                        <h1 class="error">Configuration Error</h1>
                        <p>Authentication system is not properly configured.</p>
                    </body>
                    </html>
                """
            }

        # Build redirect URI for Cognito callback
        redirect_uri = f"https://{host}{base_path}/auth/callback"

        # Build Cognito authorization URL
        auth_params = urllib.parse.urlencode({
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': 'openid email profile',
            'state': urllib.parse.quote(redirect_to)  # Preserve original destination
        })

        cognito_url = f"https://{cognito_domain}.auth.{region}.amazoncognito.com/login?{auth_params}"

        # Clear the old session cookie when redirecting to login
        # This ensures a fresh session is created after re-authentication
        clear_session_cookie = f"session_id=; HttpOnly; Secure; SameSite=Lax; Path={base_path or '/'}; Max-Age=0"

        return {
            'statusCode': 302,
            'multiValueHeaders': {
                'Set-Cookie': [clear_session_cookie]
            },
            'headers': {
                'Location': cognito_url,
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            },
            'body': ''
        }

    except Exception as e:
        print(f"Auth decider error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Internal server error'
        }
