import json
import os
import time
import base64
from typing import Dict, Any, Optional
import urllib.request
import urllib.error
import urllib.parse

import boto3
from jose import jwt, jwk
from jose.exceptions import ExpiredSignatureError


# DynamoDB client (initialized once for connection reuse)
dynamodb = boto3.resource('dynamodb')

# Cache for JWKS keys
_jwks_cache = None
_jwks_cache_time = 0
JWKS_CACHE_DURATION = 3600  # 1 hour in seconds


def get_jwks(region: str, user_pool_id: str) -> Dict[str, Any]:
    """Fetch and cache JWKS keys from Cognito."""
    global _jwks_cache, _jwks_cache_time

    current_time = time.time()
    if _jwks_cache and (current_time - _jwks_cache_time) < JWKS_CACHE_DURATION:
        return _jwks_cache

    jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"

    try:
        with urllib.request.urlopen(jwks_url) as response:
            _jwks_cache = json.loads(response.read())
            _jwks_cache_time = current_time
            return _jwks_cache
    except Exception as e:
        print(f"Failed to fetch JWKS: {str(e)}")
        raise


def verify_jwt(token: str, region: str, user_pool_id: str, client_id: str) -> Dict[str, Any]:
    """Verify and decode a Cognito JWT token."""
    try:
        # Get JWKS keys
        jwks_data = get_jwks(region, user_pool_id)

        # Decode token header to get key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        # Find the matching key
        key = None
        for k in jwks_data['keys']:
            if k['kid'] == kid:
                key = k
                break

        if not key:
            raise ValueError(f"Unable to find a signing key that matches: {kid}")

        # Construct the public key
        public_key = jwk.construct(key)

        # Verify and decode the token
        message, encoded_signature = token.rsplit('.', 1)
        decoded_signature = base64.urlsafe_b64decode(encoded_signature + '==')

        if not public_key.verify(message.encode(), decoded_signature):
            raise ValueError("Signature verification failed")

        # Decode the token
        claims = jwt.get_unverified_claims(token)

        # Verify claims
        current_time = time.time()

        # Check expiration
        if 'exp' in claims and claims['exp'] < current_time:
            raise ExpiredSignatureError("Token has expired")

        # Check issuer
        expected_issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        if claims.get('iss') != expected_issuer:
            raise ValueError(f"Invalid issuer: {claims.get('iss')}")

        # For id_token, verify audience (client_id)
        if claims.get('token_use') == 'id' and claims.get('aud') != client_id:
            raise ValueError(f"Invalid audience: {claims.get('aud')}")

        # For access_token, verify client_id claim
        if claims.get('token_use') == 'access' and claims.get('client_id') != client_id:
            raise ValueError(f"Invalid client_id: {claims.get('client_id')}")

        return claims

    except ExpiredSignatureError:
        raise
    except Exception as e:
        print(f"JWT verification failed: {str(e)}")
        raise


def extract_session_id_from_event(event: Dict[str, Any]) -> Optional[str]:
    """Extract session_id from cookies."""
    headers = event.get('headers', {})
    cookie_header = headers.get('Cookie', '')

    if cookie_header:
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

        session = response['Item']

        # Check if session has expired (belt and suspenders - TTL should handle this)
        current_time = int(time.time())
        if session.get('expiresAt', 0) < current_time:
            print(f"Session expired: {session_id[:8]}...")
            return None

        return session

    except Exception as e:
        print(f"DynamoDB lookup failed: {str(e)}")
        return None


def update_session_last_accessed(session_id: str) -> None:
    """Update lastAccessedAt timestamp for session."""
    table_name = os.environ.get('USER_SESSIONS_TABLE')
    if not table_name:
        return

    try:
        table = dynamodb.Table(table_name)
        table.update_item(
            Key={'sessionId': session_id},
            UpdateExpression='SET lastAccessedAt = :time',
            ExpressionAttributeValues={':time': int(time.time())}
        )
    except Exception as e:
        # Non-critical - don't fail auth for this
        print(f"Failed to update lastAccessedAt: {str(e)}")


def generate_policy(principal_id: str, effect: str, resource: str, context: Dict[str, str] = None) -> Dict[str, Any]:
    """Generate IAM policy for API Gateway."""
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }

    if context:
        # Convert all context values to strings (API Gateway requirement)
        policy['context'] = {k: str(v) for k, v in context.items()}

    return policy


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda authorizer handler - validates sessions from DynamoDB."""
    print(f"Authorizer event: {json.dumps(event, default=str)}")

    try:
        # Check if this is a public route
        path = event.get('path') or event.get('resource', '')
        method_arn = event.get('methodArn', '*')

        # Public routes that don't require authentication
        public_routes = ['/auth/callback', '/auth/decider']

        if any(route in path for route in public_routes):
            print(f"Public route detected: {path}")
            return generate_policy('anonymous', 'Allow', method_arn, {
                'isPublicRoute': 'true'
            })

        # Extract session_id from cookie
        session_id = extract_session_id_from_event(event)

        if not session_id:
            print("No session_id cookie found - unauthorized")
            raise Exception("Unauthorized")

        # Look up session from DynamoDB
        session = get_session_from_dynamodb(session_id)

        if not session:
            print("Session not found or expired - unauthorized")
            raise Exception("Unauthorized - Session not found")

        # Get tokens from session (stored server-side)
        id_token = session.get('idToken')

        if not id_token:
            print("No id_token in session - unauthorized")
            raise Exception("Unauthorized - Invalid session")

        # Get environment variables
        region = os.environ.get('AWS_REGION', 'us-east-1')
        user_pool_id = os.environ.get('COGNITO_USER_POOL_ID')
        client_id = os.environ.get('COGNITO_CLIENT_ID')

        if not user_pool_id or not client_id:
            raise ValueError("Missing required environment variables")

        # Verify token from DynamoDB
        try:
            claims = verify_jwt(id_token, region, user_pool_id, client_id)

            # Extract user information from verified claims
            user_id = claims.get('sub') or claims.get('cognito:username', 'unknown')
            email = claims.get('email', session.get('email', 'unknown'))
            username = claims.get('cognito:username') or email

            print(f"Session verified for user: {user_id}")

            # Update last accessed time (async-friendly, non-blocking failure)
            update_session_last_accessed(session_id)

            # Allow all resources under this API
            arn_parts = method_arn.split('/')
            if len(arn_parts) >= 2:
                base_arn = '/'.join(arn_parts[:2])
                allowed_arn = f"{base_arn}/*"
            else:
                allowed_arn = method_arn

            return generate_policy(user_id, 'Allow', allowed_arn, {
                'userId': user_id,
                'email': email,
                'username': username,
                'sessionId': session_id,
                'tokenType': claims.get('token_use', 'unknown'),
                'exp': str(claims.get('exp', 0))
            })

        except ExpiredSignatureError:
            print("Token in session has expired - needs refresh")

            # Check if session has refresh token
            refresh_token = session.get('refreshToken')
            if refresh_token:
                print("Session has refresh token - redirecting to decider")
                # Return context indicating refresh is needed
                # The decider endpoint will handle the actual refresh
                raise Exception("Unauthorized - Token expired - Refresh available")

            # No refresh token - full re-auth needed
            raise Exception("Unauthorized - Token expired")

        except Exception as e:
            print(f"Token verification failed: {str(e)}")
            raise Exception("Unauthorized - Invalid token")

    except Exception as e:
        print(f"Authorizer error: {str(e)}")
        # Re-raise if it's an Unauthorized exception
        if "Unauthorized" in str(e):
            raise
        # For other errors, deny access
        return generate_policy('user', 'Deny', event.get('methodArn', '*'), {
            'error': 'authorizer_error'
        })
