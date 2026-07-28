"""
Lambda function to handle user logout.

This function:
1. Extracts session ID from HttpOnly cookie
2. Deletes the session from DynamoDB
3. Clears the session cookie
4. Returns success response
"""

import json
import os
from typing import Dict, Any
import boto3

from security_headers import get_security_headers

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get('USER_SESSIONS_TABLE', 'static-site-sessions')
table = dynamodb.Table(table_name)


def extract_session_id(event: Dict[str, Any]) -> str:
    """
    Extract session ID from HttpOnly cookie.

    Returns:
        Session ID string or empty string if not found
    """
    cookies = event.get('headers', {}).get('Cookie', '') or event.get('headers', {}).get('cookie', '')

    if not cookies:
        return ''

    # Parse cookies to find session_id
    for cookie in cookies.split(';'):
        cookie = cookie.strip()
        if cookie.startswith('session_id='):
            return cookie.split('=', 1)[1]

    return ''


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle logout request.

    Steps:
    1. Extract session ID from cookie
    2. Delete session from DynamoDB
    3. Clear the session cookie
    4. Return success response
    """

    print("Logout request received")

    # Extract session ID from cookie
    session_id = extract_session_id(event)

    if not session_id:
        print("No session ID found in request")
        # Still return success and clear cookie (idempotent)
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Set-Cookie': 'session_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax',
                **get_security_headers()
            },
            'body': json.dumps({
                'success': True,
                'message': 'Logged out successfully'
            })
        }

    # Delete session from DynamoDB
    try:
        table.delete_item(
            Key={'sessionId': session_id}
        )
        # Log a prefix only - a full session ID in CloudWatch is a live credential.
        print(f"Session {session_id[:8]}... deleted from DynamoDB")
    except Exception as e:
        # Log error but still clear cookie (best effort)
        print(f"Error deleting session from DynamoDB: {str(e)}")
        # Continue to clear cookie even if DynamoDB delete fails

    # Clear the session cookie and return success
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            # Clear cookie by setting Max-Age=0
            'Set-Cookie': 'session_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax',
            **get_security_headers()
        },
        'body': json.dumps({
            'success': True,
            'message': 'Logged out successfully'
        })
    }
