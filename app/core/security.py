from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import HTTPException, status

from app.core.config import settings

_ALGORITHM = settings.JWT_ALGORITHM
_SECRET = settings.JWT_SECRET


def create_token(payload: dict[str, Any], expires: timedelta) -> str:
    """Sign a JWT with an expiry. Caller supplies all claims except `iat`/`exp`."""
    now = datetime.now(UTC)
    data = {**payload, "iat": now, "exp": now + expires}
    return jwt.encode(data, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises HTTP 401 on any failure."""
    try:
        return jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def create_access_token(user_id: str) -> str:
    return create_token(
        {"sub": user_id, "purpose": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES),
    )


def create_verification_token(email: str) -> str:
    return create_token(
        {"sub": email, "purpose": "email_verify"},
        timedelta(hours=settings.VERIFICATION_TOKEN_TTL_HOURS),
    )


def create_oauth_state_token() -> str:
    """Short-lived state token to prevent CSRF in OAuth flows."""
    return create_token({"purpose": "oauth_state"}, timedelta(minutes=10))
