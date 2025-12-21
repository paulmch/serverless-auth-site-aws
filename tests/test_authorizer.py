"""Tests for the Lambda authorizer - security-critical path."""
import time
import pytest
from unittest.mock import patch, MagicMock
from jose.exceptions import ExpiredSignatureError


class TestSessionExtraction:
    """Test session_id extraction from cookies."""

    def test_extract_session_id_from_valid_cookie(self):
        """Should extract session_id from Cookie header."""
        from authorizer import extract_session_id_from_event

        event = {
            'headers': {
                'Cookie': 'session_id=abc-123-def; other=value'
            }
        }
        result = extract_session_id_from_event(event)
        assert result == 'abc-123-def'

    def test_extract_session_id_url_encoded(self):
        """Should handle URL-encoded session_id."""
        from authorizer import extract_session_id_from_event

        event = {
            'headers': {
                'Cookie': 'session_id=abc%2D123%2Ddef'
            }
        }
        result = extract_session_id_from_event(event)
        assert result == 'abc-123-def'

    def test_missing_cookie_header(self):
        """Should return None when Cookie header is missing."""
        from authorizer import extract_session_id_from_event

        event = {'headers': {}}
        result = extract_session_id_from_event(event)
        assert result is None

    def test_missing_session_id_cookie(self):
        """Should return None when session_id cookie is not present."""
        from authorizer import extract_session_id_from_event

        event = {
            'headers': {
                'Cookie': 'other=value; another=thing'
            }
        }
        result = extract_session_id_from_event(event)
        assert result is None


class TestSessionLookup:
    """Test DynamoDB session lookup."""

    @patch('authorizer.dynamodb')
    def test_valid_session_lookup(self, mock_dynamodb, valid_session):
        """Should return session when found and not expired."""
        from authorizer import get_session_from_dynamodb

        mock_table = MagicMock()
        mock_table.get_item.return_value = {'Item': valid_session}
        mock_dynamodb.Table.return_value = mock_table

        result = get_session_from_dynamodb('session-uuid-123')

        assert result is not None
        assert result['sessionId'] == 'session-uuid-123'
        mock_table.get_item.assert_called_once_with(Key={'sessionId': 'session-uuid-123'})

    @patch('authorizer.dynamodb')
    def test_session_not_found(self, mock_dynamodb):
        """Should return None when session doesn't exist."""
        from authorizer import get_session_from_dynamodb

        mock_table = MagicMock()
        mock_table.get_item.return_value = {}  # No 'Item' key
        mock_dynamodb.Table.return_value = mock_table

        result = get_session_from_dynamodb('nonexistent-session')

        assert result is None

    @patch('authorizer.dynamodb')
    def test_expired_session(self, mock_dynamodb, expired_session):
        """Should return None when session has expired."""
        from authorizer import get_session_from_dynamodb

        mock_table = MagicMock()
        mock_table.get_item.return_value = {'Item': expired_session}
        mock_dynamodb.Table.return_value = mock_table

        result = get_session_from_dynamodb('session-uuid-123')

        assert result is None

    @patch('authorizer.dynamodb')
    def test_dynamodb_error(self, mock_dynamodb):
        """Should return None on DynamoDB errors."""
        from authorizer import get_session_from_dynamodb

        mock_table = MagicMock()
        mock_table.get_item.side_effect = Exception("DynamoDB error")
        mock_dynamodb.Table.return_value = mock_table

        result = get_session_from_dynamodb('session-uuid-123')

        assert result is None


class TestJWTVerification:
    """Test JWT token verification."""

    @patch('authorizer.get_jwks')
    def test_expired_token_raises_exception(self, mock_get_jwks, expired_jwt_claims):
        """Should raise ExpiredSignatureError for expired tokens."""
        from authorizer import verify_jwt
        import base64
        import json

        # Create a properly formatted mock JWT (header.payload.signature)
        header = base64.urlsafe_b64encode(json.dumps({'kid': 'test-key-id', 'alg': 'RS256'}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps(expired_jwt_claims).encode()).rstrip(b'=').decode()
        mock_token = f"{header}.{payload}.fake-signature"

        mock_get_jwks.return_value = {
            'keys': [{'kid': 'test-key-id', 'kty': 'RSA', 'n': 'test-n', 'e': 'AQAB'}]
        }

        with patch('authorizer.jwk.construct') as mock_jwk:
            mock_key = MagicMock()
            mock_key.verify.return_value = True
            mock_jwk.return_value = mock_key

            with pytest.raises(ExpiredSignatureError):
                verify_jwt(mock_token, 'us-east-1', 'us-east-1_TestPool', 'test-client-id')

    @patch('authorizer.get_jwks')
    def test_invalid_issuer_raises_exception(self, mock_get_jwks, valid_jwt_claims):
        """Should raise ValueError for invalid issuer."""
        from authorizer import verify_jwt
        import base64
        import json

        # Modify claims to have wrong issuer
        claims = valid_jwt_claims.copy()
        claims['iss'] = 'https://wrong-issuer.com'

        header = base64.urlsafe_b64encode(json.dumps({'kid': 'test-key-id', 'alg': 'RS256'}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
        mock_token = f"{header}.{payload}.fake-signature"

        mock_get_jwks.return_value = {
            'keys': [{'kid': 'test-key-id', 'kty': 'RSA', 'n': 'test-n', 'e': 'AQAB'}]
        }

        with patch('authorizer.jwk.construct') as mock_jwk:
            mock_key = MagicMock()
            mock_key.verify.return_value = True
            mock_jwk.return_value = mock_key

            with pytest.raises(ValueError, match="Invalid issuer"):
                verify_jwt(mock_token, 'us-east-1', 'us-east-1_TestPool', 'test-client-id')

    @patch('authorizer.get_jwks')
    def test_invalid_audience_raises_exception(self, mock_get_jwks, valid_jwt_claims):
        """Should raise ValueError for invalid audience on id_token."""
        from authorizer import verify_jwt
        import base64
        import json

        # Modify claims to have wrong audience
        claims = valid_jwt_claims.copy()
        claims['aud'] = 'wrong-client-id'

        header = base64.urlsafe_b64encode(json.dumps({'kid': 'test-key-id', 'alg': 'RS256'}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
        mock_token = f"{header}.{payload}.fake-signature"

        mock_get_jwks.return_value = {
            'keys': [{'kid': 'test-key-id', 'kty': 'RSA', 'n': 'test-n', 'e': 'AQAB'}]
        }

        with patch('authorizer.jwk.construct') as mock_jwk:
            mock_key = MagicMock()
            mock_key.verify.return_value = True
            mock_jwk.return_value = mock_key

            with pytest.raises(ValueError, match="Invalid audience"):
                verify_jwt(mock_token, 'us-east-1', 'us-east-1_TestPool', 'test-client-id')

    @patch('authorizer.get_jwks')
    def test_missing_signing_key_raises_exception(self, mock_get_jwks):
        """Should raise ValueError when signing key not found in JWKS."""
        from authorizer import verify_jwt

        mock_get_jwks.return_value = {
            'keys': [{'kid': 'different-key-id', 'kty': 'RSA', 'n': 'test-n', 'e': 'AQAB'}]
        }

        with patch('authorizer.jwt.get_unverified_header') as mock_header:
            mock_header.return_value = {'kid': 'test-key-id'}

            with pytest.raises(ValueError, match="Unable to find a signing key"):
                verify_jwt('token', 'us-east-1', 'us-east-1_TestPool', 'test-client-id')


class TestPolicyGeneration:
    """Test IAM policy generation."""

    def test_allow_policy(self):
        """Should generate Allow policy with context."""
        from authorizer import generate_policy

        policy = generate_policy(
            'user-123',
            'Allow',
            'arn:aws:execute-api:us-east-1:123456789:api-id/prod/GET/',
            {'userId': 'user-123', 'email': 'test@example.com'}
        )

        assert policy['principalId'] == 'user-123'
        assert policy['policyDocument']['Statement'][0]['Effect'] == 'Allow'
        assert policy['context']['userId'] == 'user-123'
        assert policy['context']['email'] == 'test@example.com'

    def test_deny_policy(self):
        """Should generate Deny policy."""
        from authorizer import generate_policy

        policy = generate_policy('user', 'Deny', 'arn:aws:execute-api:*')

        assert policy['policyDocument']['Statement'][0]['Effect'] == 'Deny'


class TestPublicRoutes:
    """Test public route handling."""

    @patch('authorizer.get_session_from_dynamodb')
    def test_auth_callback_is_public(self, mock_get_session, api_gateway_event, mock_context):
        """Should allow /auth/callback without authentication."""
        from authorizer import handler

        event = api_gateway_event.copy()
        event['path'] = '/auth/callback'
        event['headers'] = {}  # No cookies

        result = handler(event, mock_context)

        assert result['policyDocument']['Statement'][0]['Effect'] == 'Allow'
        assert result['context']['isPublicRoute'] == 'true'
        mock_get_session.assert_not_called()

    @patch('authorizer.get_session_from_dynamodb')
    def test_auth_decider_is_public(self, mock_get_session, api_gateway_event, mock_context):
        """Should allow /auth/decider without authentication."""
        from authorizer import handler

        event = api_gateway_event.copy()
        event['path'] = '/auth/decider'
        event['headers'] = {}  # No cookies

        result = handler(event, mock_context)

        assert result['policyDocument']['Statement'][0]['Effect'] == 'Allow'
        mock_get_session.assert_not_called()


class TestAuthorizerHandler:
    """Test the main authorizer handler."""

    @patch('authorizer.verify_jwt')
    @patch('authorizer.get_session_from_dynamodb')
    def test_valid_session_allows_access(
        self, mock_get_session, mock_verify_jwt,
        api_gateway_event, mock_context, valid_session, valid_jwt_claims
    ):
        """Should allow access with valid session and token."""
        from authorizer import handler

        mock_get_session.return_value = valid_session
        mock_verify_jwt.return_value = valid_jwt_claims

        result = handler(api_gateway_event, mock_context)

        assert result['policyDocument']['Statement'][0]['Effect'] == 'Allow'
        assert result['principalId'] == 'user-123'
        assert result['context']['email'] == 'test@example.com'

    @patch('authorizer.get_session_from_dynamodb')
    def test_missing_session_cookie_denies_access(
        self, mock_get_session, api_gateway_event, mock_context
    ):
        """Should deny access when session_id cookie is missing."""
        from authorizer import handler

        event = api_gateway_event.copy()
        event['headers'] = {}  # No cookies

        with pytest.raises(Exception, match="Unauthorized"):
            handler(event, mock_context)

    @patch('authorizer.get_session_from_dynamodb')
    def test_session_not_found_denies_access(
        self, mock_get_session, api_gateway_event, mock_context
    ):
        """Should deny access when session not found in DynamoDB."""
        from authorizer import handler

        mock_get_session.return_value = None

        with pytest.raises(Exception, match="Unauthorized"):
            handler(api_gateway_event, mock_context)

    @patch('authorizer.verify_jwt')
    @patch('authorizer.get_session_from_dynamodb')
    def test_expired_token_with_refresh_token(
        self, mock_get_session, mock_verify_jwt,
        api_gateway_event, mock_context, valid_session
    ):
        """Should indicate refresh available when token expired but refresh token exists."""
        from authorizer import handler

        mock_get_session.return_value = valid_session
        mock_verify_jwt.side_effect = ExpiredSignatureError("Token expired")

        with pytest.raises(Exception, match="Refresh available"):
            handler(api_gateway_event, mock_context)

    @patch('authorizer.verify_jwt')
    @patch('authorizer.get_session_from_dynamodb')
    def test_expired_token_without_refresh_token(
        self, mock_get_session, mock_verify_jwt,
        api_gateway_event, mock_context, valid_session
    ):
        """Should deny when token expired and no refresh token."""
        from authorizer import handler

        session = valid_session.copy()
        session['refreshToken'] = ''  # No refresh token
        mock_get_session.return_value = session
        mock_verify_jwt.side_effect = ExpiredSignatureError("Token expired")

        with pytest.raises(Exception, match="Token expired"):
            handler(api_gateway_event, mock_context)
