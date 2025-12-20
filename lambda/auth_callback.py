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


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle OAuth2 callback from Cognito."""
    print(f"Auth callback event: {json.dumps(event, default=str)}")

    try:
        # Extract query parameters
        query_params = event.get('queryStringParameters') or {}
        code = query_params.get('code')
        error = query_params.get('error')

        # Handle errors from Cognito
        if error:
            error_description = query_params.get('error_description', 'Unknown error')
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'text/html',
                    'Cache-Control': 'no-cache, no-store, must-revalidate'
                },
                'body': f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Authentication Error</title>
                        <meta charset="utf-8">
                        <style>
                            body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                            .error {{ color: #d32f2f; }}
                            a {{ color: #1976d2; text-decoration: none; }}
                        </style>
                    </head>
                    <body>
                        <h1 class="error">Authentication Error</h1>
                        <p>{error}: {error_description}</p>
                        <p><a href="/">Return to Home</a></p>
                    </body>
                    </html>
                """
            }

        # Validate code parameter
        if not code:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'text/plain'},
                'body': 'Missing authorization code'
            }

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
            session_ttl = 30 * 24 * 3600  # 30 days
            session_cookie = f"session_id={session_id}; HttpOnly; Secure; SameSite=Lax; Path={base_path or '/'}; Max-Age={session_ttl}"

            # Redirect to home page
            redirect_location = base_path if base_path else "/"
            return {
                'statusCode': 302,
                'multiValueHeaders': {
                    'Set-Cookie': [session_cookie]
                },
                'headers': {
                    'Location': redirect_location,
                    'Cache-Control': 'no-cache, no-store, must-revalidate'
                },
                'body': ''
            }

        except Exception as e:
            print(f"Token exchange error: {str(e)}")
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
                        <title>Authentication Failed</title>
                        <meta charset="utf-8">
                        <style>
                            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                            .error { color: #d32f2f; }
                            a { color: #1976d2; text-decoration: none; }
                        </style>
                    </head>
                    <body>
                        <h1 class="error">Authentication Failed</h1>
                        <p>Unable to complete the authentication process.</p>
                        <p><a href="/">Try Again</a></p>
                    </body>
                    </html>
                """
            }

    except Exception as e:
        print(f"Auth callback error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Internal server error'
        }
