"""
Tests for:
  GET /api/v1/auth/verify-email
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_verification_token,
)
from app.models.enums import UserProvider
from app.models.user import User
from app.schemas.auth import TokenResponse
from app.services import auth as auth_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALGO = settings.JWT_ALGORITHM
_SECRET = settings.JWT_SECRET


def _make_user(
    *,
    email: str = "alice@example.com",
    email_verified: bool = False,
    provider: UserProvider = UserProvider.EMAIL,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        provider=provider,
        email_verified=email_verified,
        is_active=True,
    )
    return user


def _make_request(headers: dict[str, str] | None = None, host: str | None = "test"):
    request = MagicMock()
    request.headers = headers or {}
    request.client = MagicMock(host=host) if host else None
    return request


# ---------------------------------------------------------------------------
# Email/password auth
# ---------------------------------------------------------------------------


class TestEmailPasswordAuth:
    async def test_register_sends_verification_without_printing_token(self, client):
        user = _make_user(email="new@example.com")

        with (
            patch(
                "app.api.v1.endpoints.auth.register_user",
                new=AsyncMock(return_value=user),
            ) as register_user,
            patch("app.api.v1.endpoints.auth.send_verification_email") as send_email,
            patch("builtins.print") as print_mock,
        ):
            resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": user.email,
                    "password": "correct horse battery staple",
                    "display_name": "New User",
                },
            )

        assert resp.status_code == 201
        register_user.assert_awaited_once()
        send_email.assert_called_once()
        assert send_email.call_args.args[0] == user.email
        print_mock.assert_not_called()

    async def test_logout_revokes_refresh_token_without_access_token(self, client):
        with patch(
            "app.api.v1.endpoints.auth.logout_user",
            new=AsyncMock(),
        ) as logout_user:
            resp = await client.post(
                "/api/v1/auth/logout",
                json={"refresh_token": "raw-refresh-token"},
            )

        assert resp.status_code == 200
        logout_user.assert_awaited_once()

    async def test_refresh_rejects_empty_refresh_token(self, client):
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": ""},
        )

        assert resp.status_code == 422

    def test_token_response_refresh_token_is_optional(self):
        response = TokenResponse(access_token="access")

        assert response.refresh_token is None

    async def test_login_unknown_user_returns_401(self):
        with (
            patch(
                "app.services.auth.get_user_by_email",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            await auth_service.login_user(
                MagicMock(),
                "missing@example.com",
                "wrong-password",
                request=_make_request(),
            )

        assert exc_info.value.status_code == 401

    async def test_create_refresh_token_uses_uuid_and_request_metadata(self):
        db = MagicMock()
        user = _make_user(email="refresh@example.com")

        raw, record = await auth_service._create_refresh_token(
            db,
            user,
            user_agent="pytest",
            ip_address="203.0.113.10",
        )

        assert raw
        assert record.user_id == user.id
        assert record.user_agent == "pytest"
        assert record.ip_address == "203.0.113.10"
        db.add.assert_called_once_with(record)


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------


class TestVerifyEmail:
    async def test_happy_path(self, client):
        """Valid verification token marks user as verified."""
        user = _make_user(email="bob@example.com")
        token = create_verification_token(user.email)

        with (
            patch(
                "app.api.v1.endpoints.auth.get_user_by_email",
                new=AsyncMock(return_value=user),
            ),
            patch("app.api.v1.endpoints.auth.DBSession", None),
        ):
            resp = await client.get(
                f"/api/v1/auth/verify-email?token={token}",
            )

        assert resp.status_code == 200
        assert resp.json()["message"] == "Email verified successfully"
        assert user.email_verified is True

    async def test_already_verified(self, client):
        user = _make_user(email="already@example.com", email_verified=True)
        token = create_verification_token(user.email)

        with patch(
            "app.api.v1.endpoints.auth.get_user_by_email",
            new=AsyncMock(return_value=user),
        ):
            resp = await client.get(f"/api/v1/auth/verify-email?token={token}")

        assert resp.status_code == 200
        assert resp.json()["message"] == "Email already verified"

    async def test_expired_token(self, client):
        expired_payload = {
            "sub": "expired@example.com",
            "purpose": "email_verify",
            "iat": datetime.now(UTC) - timedelta(hours=48),
            "exp": datetime.now(UTC) - timedelta(hours=24),
        }
        expired_token = jwt.encode(expired_payload, _SECRET, algorithm=_ALGO)
        resp = await client.get(f"/api/v1/auth/verify-email?token={expired_token}")
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    async def test_invalid_token(self, client):
        resp = await client.get("/api/v1/auth/verify-email?token=not.a.valid.jwt")
        assert resp.status_code == 401

    async def test_wrong_purpose_token(self, client):
        """Access token must not work as a verification token."""
        fake_user = _make_user()
        access_token = create_access_token(str(fake_user.id))
        resp = await client.get(f"/api/v1/auth/verify-email?token={access_token}")
        assert resp.status_code == 400

    async def test_user_not_found(self, client):
        token = create_verification_token("ghost@example.com")
        with patch(
            "app.api.v1.endpoints.auth.get_user_by_email",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.get(f"/api/v1/auth/verify-email?token={token}")
        assert resp.status_code == 404
