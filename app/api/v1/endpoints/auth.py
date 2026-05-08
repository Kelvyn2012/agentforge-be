import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.db.session import get_session
from app.schemas.auth import MessageResponse
from app.services.auth import get_user_by_email

from app.api.deps import DBSession

router = APIRouter()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------


@router.get(
    "/verify-email",
    response_model=MessageResponse,
    summary="Verify email address via signed token",
)
async def verify_email(
    db: DBSession,
    token: str = Query(..., description="Signed JWT from the verification email"),
) -> MessageResponse:
    payload = decode_token(token)
    if payload.get("purpose") != "email_verify":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token purpose",
        )
    email: str | None = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing subject",
        )
    user = await get_user_by_email(db, email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    if user.email_verified:
        return MessageResponse(message="Email already verified")

    user.email_verified = True
    await db.commit()
    return MessageResponse(message="Email verified successfully")
