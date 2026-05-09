import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from app.models.enums import UserProvider
from app.models.refresh_token import RefreshToken
from app.models.user import User


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def register_user(
    db: AsyncSession,
    email: str,
    password: str,
    display_name: str | None = None,
) -> User:
    email = email.lower()

    existing = await get_user_by_email(db, email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        display_name=display_name,
        password_hash=hash_password(password),
        provider=UserProvider.EMAIL,
        email_verified=False,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    await db.refresh(user)
    return user


async def login_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> tuple[str, str]:
    user = await get_user_by_email(db, email.lower())

    dummy_hash = "$2b$12$KIXCfJMCfucPqmBxmzmpFuGHGSsXgEJ9Eq/ztV9bPYhZDi7p3eDMq"
    stored_hash = user.password_hash if user else dummy_hash

    if not verify_password(password, stored_hash) or user is None:  # pyright: ignore[reportArgumentType]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in",
        )

    access_token = create_access_token(str(user.id))
    raw_refresh, _ = await _create_refresh_token(db, user)
    await db.commit()

    return access_token, raw_refresh


async def logout_user(db: AsyncSession, raw_token: str) -> None:
    token_hash = hash_refresh_token(raw_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    record = result.scalar_one_or_none()
    if record and not record.revoked:
        record.revoked = True
        await db.commit()


async def rotate_refresh_token(
    db: AsyncSession,
    raw_token: str,
    request: Request,
) -> tuple[str, str]:
    token_hash = hash_refresh_token(raw_token)

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    record = result.scalar_one_or_none()

    _validate_refresh_record(record)

    record.revoked = True  # type: ignore

    user = await get_user_by_id(db, record.user_id)  # type: ignore[union-attr]
    if user is None or not user.is_active:
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(str(user.id))
    raw_refresh, _ = await _create_refresh_token(db, user)
    await db.commit()

    return access_token, raw_refresh


def _validate_refresh_record(record: RefreshToken | None) -> None:
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found",
        )
    if record.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )
    if record.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )


async def _create_refresh_token(
    db: AsyncSession, user: User
) -> tuple[str, RefreshToken]:
    raw = generate_refresh_token()
    record = RefreshToken(
        token_hash=hash_refresh_token(raw),
        user_id=str(user.id),
        expires_at=refresh_token_expiry(),
    )
    db.add(record)
    return raw, record
