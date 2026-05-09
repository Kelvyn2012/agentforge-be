"""
Tests for:
  GET /api/v1/auth/verify-email
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import jwt

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_verification_token,
)
from app.models.enums import UserProvider
from app.models.user import User

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
