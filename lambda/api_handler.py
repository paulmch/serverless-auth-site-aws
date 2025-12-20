import json
from typing import Dict, Any


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
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
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
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'authenticated': True})
        }

    return {
        'statusCode': 404,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'error': 'Not found'})
    }
