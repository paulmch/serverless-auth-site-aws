import json
from typing import Dict, Any


def get_security_headers() -> Dict[str, str]:
    """
    Return security headers following OWASP best practices.

    Note: CORS headers are not needed since frontend is served from
    same API Gateway origin (same-origin policy applies).
    """
    return {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-XSS-Protection': '1; mode=block',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache'
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Simple API handler demonstrating authenticated access."""

    # Get user info from authorizer context
    request_context = event.get('requestContext', {})
    authorizer_context = request_context.get('authorizer', {})

    path = event.get('path', '')

    if '/api/user' in path or '/api/auth/user' in path:
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                **get_security_headers()
            },
            'body': json.dumps({
                'userId': authorizer_context.get('userId', 'unknown'),
                'email': authorizer_context.get('email', 'unknown'),
                'username': authorizer_context.get('username', 'unknown'),
                'message': 'You are authenticated!'
            })
        }

    if '/api/auth/check' in path:
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                **get_security_headers()
            },
            'body': json.dumps({'authenticated': True})
        }

    return {
        'statusCode': 404,
        'headers': {
            'Content-Type': 'application/json',
            **get_security_headers()
        },
        'body': json.dumps({'error': 'Not found'})
    }
