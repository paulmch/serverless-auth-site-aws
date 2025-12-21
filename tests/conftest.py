"""Shared test fixtures for Lambda function tests."""
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda'))

# Set required environment variables before importing modules
os.environ['AWS_REGION'] = 'us-east-1'
os.environ['COGNITO_USER_POOL_ID'] = 'us-east-1_TestPool'
os.environ['COGNITO_CLIENT_ID'] = 'test-client-id'
os.environ['COGNITO_DOMAIN'] = 'test-domain'
os.environ['USER_SESSIONS_TABLE'] = 'test-sessions'
os.environ['STATIC_BUCKET'] = 'test-bucket'


@pytest.fixture
def valid_jwt_claims():
    """Valid JWT claims for testing."""
    return {
        'sub': 'user-123',
        'email': 'test@example.com',
        'cognito:username': 'testuser',
        'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool',
        'aud': 'test-client-id',
        'client_id': 'test-client-id',
        'token_use': 'id',
        'exp': int(time.time()) + 3600,  # Valid for 1 hour
        'iat': int(time.time()),
    }


@pytest.fixture
def expired_jwt_claims(valid_jwt_claims):
    """Expired JWT claims for testing."""
    claims = valid_jwt_claims.copy()
    claims['exp'] = int(time.time()) - 3600  # Expired 1 hour ago
    return claims


@pytest.fixture
def valid_session():
    """Valid session data from DynamoDB."""
    return {
        'sessionId': 'session-uuid-123',
        'userId': 'user-123',
        'email': 'test@example.com',
        'username': 'testuser',
        'idToken': 'valid-id-token',
        'accessToken': 'valid-access-token',
        'refreshToken': 'valid-refresh-token',
        'createdAt': int(time.time()),
        'lastAccessedAt': int(time.time()),
        'expiresAt': int(time.time()) + 86400 * 30,  # 30 days
    }


@pytest.fixture
def expired_session(valid_session):
    """Expired session data."""
    session = valid_session.copy()
    session['expiresAt'] = int(time.time()) - 3600  # Expired 1 hour ago
    return session


@pytest.fixture
def api_gateway_event():
    """Base API Gateway event for authorizer."""
    return {
        'type': 'REQUEST',
        'methodArn': 'arn:aws:execute-api:us-east-1:123456789:api-id/prod/GET/',
        'resource': '/',
        'path': '/',
        'httpMethod': 'GET',
        'headers': {
            'Host': 'api.example.com',
            'Cookie': 'session_id=session-uuid-123',
        },
        'requestContext': {
            'stage': 'prod',
            'resourcePath': '/',
            'httpMethod': 'GET',
            'identity': {
                'sourceIp': '1.2.3.4',
                'userAgent': 'Mozilla/5.0',
            },
        },
    }


@pytest.fixture
def mock_dynamodb_table():
    """Mock DynamoDB table."""
    mock_table = MagicMock()
    return mock_table


@pytest.fixture
def mock_context():
    """Mock Lambda context."""
    context = MagicMock()
    context.log_stream_name = 'test-log-stream'
    context.function_name = 'test-function'
    return context
