"""Tests for session lifecycle - create, access, refresh, expire, cleanup."""
import time
import pytest
from unittest.mock import patch, MagicMock


class TestSessionCreation:
    """Test session creation in auth_callback."""

    @patch('auth_callback.dynamodb')
    def test_store_session_creates_item(self, mock_dynamodb):
        """Should store session with all required fields."""
        from auth_callback import store_session

        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        tokens = {
            'id_token': 'test-id-token',
            'access_token': 'test-access-token',
            'refresh_token': 'test-refresh-token',
        }
        user_info = {
            'sub': 'user-123',
            'email': 'test@example.com',
            'cognito:username': 'testuser',
        }

        store_session('session-uuid', tokens, user_info)

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]['Item']

        assert item['sessionId'] == 'session-uuid'
        assert item['userId'] == 'user-123'
        assert item['email'] == 'test@example.com'
        assert item['idToken'] == 'test-id-token'
        assert item['accessToken'] == 'test-access-token'
        assert item['refreshToken'] == 'test-refresh-token'
        assert 'createdAt' in item
        assert 'expiresAt' in item
        assert item['expiresAt'] > item['createdAt']

    @patch('auth_callback.dynamodb')
    def test_store_session_handles_missing_refresh_token(self, mock_dynamodb):
        """Should handle missing refresh token gracefully."""
        from auth_callback import store_session

        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        tokens = {
            'id_token': 'test-id-token',
            'access_token': 'test-access-token',
            # No refresh_token
        }
        user_info = {'sub': 'user-123', 'email': 'test@example.com'}

        store_session('session-uuid', tokens, user_info)

        item = mock_table.put_item.call_args[1]['Item']
        assert item['refreshToken'] == ''

    @patch('auth_callback.dynamodb')
    def test_session_ttl_is_30_days(self, mock_dynamodb):
        """Should set session expiry to 30 days."""
        from auth_callback import store_session

        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        tokens = {'id_token': 'x', 'access_token': 'x', 'refresh_token': 'x'}
        user_info = {'sub': 'user-123'}

        before = int(time.time())
        store_session('session-uuid', tokens, user_info)
        after = int(time.time())

        item = mock_table.put_item.call_args[1]['Item']
        expected_ttl = 30 * 24 * 3600  # 30 days in seconds

        assert item['expiresAt'] >= before + expected_ttl
        assert item['expiresAt'] <= after + expected_ttl


class TestSessionAccess:
    """Test session access and lastAccessedAt updates."""

    @patch('authorizer.dynamodb')
    def test_update_last_accessed(self, mock_dynamodb):
        """Should update lastAccessedAt timestamp."""
        from authorizer import update_session_last_accessed

        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        before = int(time.time())
        update_session_last_accessed('session-uuid')
        after = int(time.time())

        mock_table.update_item.assert_called_once()
        call_args = mock_table.update_item.call_args

        assert call_args[1]['Key'] == {'sessionId': 'session-uuid'}
        update_time = call_args[1]['ExpressionAttributeValues'][':time']
        assert before <= update_time <= after

    @patch('authorizer.dynamodb')
    def test_update_last_accessed_handles_errors(self, mock_dynamodb):
        """Should not raise exception on update errors."""
        from authorizer import update_session_last_accessed

        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DynamoDB error")
        mock_dynamodb.Table.return_value = mock_table

        # Should not raise
        update_session_last_accessed('session-uuid')


class TestSessionRefresh:
    """Test token refresh and session update."""

    @patch('auth_decider.dynamodb')
    def test_update_session_tokens(self, mock_dynamodb):
        """Should update tokens in existing session."""
        from auth_decider import update_session_tokens

        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        # Mock jwt.get_unverified_claims
        with patch('auth_decider.jwt.get_unverified_claims') as mock_claims:
            mock_claims.return_value = {'email': 'updated@example.com'}

            tokens = {
                'id_token': 'new-id-token',
                'access_token': 'new-access-token',
            }

            result = update_session_tokens('session-uuid', tokens)

            assert result is True
            mock_table.update_item.assert_called_once()
            call_args = mock_table.update_item.call_args[1]
            assert ':id' in call_args['ExpressionAttributeValues']
            assert ':access' in call_args['ExpressionAttributeValues']

    @patch('auth_decider.dynamodb')
    def test_update_session_tokens_with_new_refresh_token(self, mock_dynamodb):
        """Should update refresh token when provided (token rotation)."""
        from auth_decider import update_session_tokens

        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        with patch('auth_decider.jwt.get_unverified_claims') as mock_claims:
            mock_claims.return_value = {'email': 'test@example.com'}

            tokens = {
                'id_token': 'new-id-token',
                'access_token': 'new-access-token',
                'refresh_token': 'new-refresh-token',  # Token rotation
            }

            result = update_session_tokens('session-uuid', tokens)

            assert result is True
            call_args = mock_table.update_item.call_args[1]
            assert 'refreshToken' in call_args['UpdateExpression']

    @patch('auth_decider.dynamodb')
    def test_update_session_tokens_handles_errors(self, mock_dynamodb):
        """Should return False on update errors."""
        from auth_decider import update_session_tokens

        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DynamoDB error")
        mock_dynamodb.Table.return_value = mock_table

        with patch('auth_decider.jwt.get_unverified_claims') as mock_claims:
            mock_claims.return_value = {'email': 'test@example.com'}

            result = update_session_tokens('session-uuid', {'id_token': 'x', 'access_token': 'x'})

            assert result is False


class TestSessionExpiry:
    """Test session expiry detection."""

    @patch('authorizer.dynamodb')
    def test_expired_session_returns_none(self, mock_dynamodb, expired_session):
        """Should return None for expired sessions."""
        from authorizer import get_session_from_dynamodb

        mock_table = MagicMock()
        mock_table.get_item.return_value = {'Item': expired_session}
        mock_dynamodb.Table.return_value = mock_table

        result = get_session_from_dynamodb('session-uuid')

        assert result is None

    @patch('authorizer.dynamodb')
    def test_valid_session_not_expired(self, mock_dynamodb, valid_session):
        """Should return session when not expired."""
        from authorizer import get_session_from_dynamodb

        mock_table = MagicMock()
        mock_table.get_item.return_value = {'Item': valid_session}
        mock_dynamodb.Table.return_value = mock_table

        result = get_session_from_dynamodb('session-uuid')

        assert result is not None
        assert result['sessionId'] == valid_session['sessionId']


class TestCookieHandling:
    """Test cookie setting and clearing."""

    @patch('auth_callback.store_session')
    @patch('auth_callback.exchange_code_for_tokens')
    def test_callback_sets_httponly_cookie(self, mock_exchange, mock_store, mock_context):
        """Should set HttpOnly session cookie after successful auth."""
        from auth_callback import handler

        mock_exchange.return_value = {
            'id_token': 'test-id-token',
            'access_token': 'test-access-token',
            'refresh_token': 'test-refresh-token',
        }

        with patch('auth_callback.jwt.get_unverified_claims') as mock_claims:
            mock_claims.return_value = {'sub': 'user-123', 'email': 'test@example.com'}

            event = {
                'queryStringParameters': {'code': 'auth-code'},
                'headers': {'Host': 'api.example.com'},
                'requestContext': {'stage': 'prod'},
            }

            result = handler(event, mock_context)

            assert result['statusCode'] == 302
            cookies = result['multiValueHeaders']['Set-Cookie']
            assert len(cookies) == 1
            cookie = cookies[0]
            assert 'session_id=' in cookie
            assert 'HttpOnly' in cookie
            assert 'Secure' in cookie
            assert 'SameSite=Lax' in cookie

    def test_decider_clears_cookie_on_login_redirect(self, mock_context):
        """Should clear session cookie when redirecting to login."""
        from auth_decider import handler

        with patch('auth_decider.get_session_from_dynamodb') as mock_get:
            mock_get.return_value = None  # No valid session

            event = {
                'queryStringParameters': {},
                'headers': {'Host': 'api.example.com', 'Cookie': 'session_id=old-session'},
                'requestContext': {'stage': 'prod'},
            }

            result = handler(event, mock_context)

            assert result['statusCode'] == 302
            cookies = result['multiValueHeaders']['Set-Cookie']
            # Should have a clear cookie (Max-Age=0)
            assert any('Max-Age=0' in c for c in cookies)
