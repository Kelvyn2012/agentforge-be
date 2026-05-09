import logging

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.api.deps import CurrentUser, DBSession
from app.core.security import create_verification_token, decode_token
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth import (
    get_user_by_email,
    login_user,
    logout_user,
    register_user,
    rotate_refresh_token,
)

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account (email + password)",
)
async def register(body: RegisterRequest, db: DBSession) -> MessageResponse:
    user = await register_user(
        db,
        email=body.email,
        password=body.password,
        display_name=body.display_name,
    )

    verification_token = create_verification_token(user.email)
    logger.info(
        "Verification token for %s: %s",
        user.email,
        verification_token,
    )
    print(verification_token)

    return MessageResponse(
        message="Account created. Check your email to verify your address."
    )


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in and receive an access + refresh token",
)
async def login(
    body: LoginRequest,
    db: DBSession,
) -> TokenResponse:
    access_token, raw_refresh = await login_user(
        db,
        email=body.email,
        password=body.password,
    )
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh)


# ---------------------------------------------------------------------------
# POST /refresh
# ---------------------------------------------------------------------------


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange a refresh token for a new access token (token rotation)",
)
async def refresh(
    request: Request,
    db: DBSession,
    payload: RefreshTokenRequest,
) -> TokenResponse:
    refresh_token = payload.refresh_token
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )
    access_token, new_raw_refresh = await rotate_refresh_token(
        db, refresh_token, request
    )
    return TokenResponse(access_token=access_token, refresh_token=new_raw_refresh)


# ---------------------------------------------------------------------------
# POST /logout
# ---------------------------------------------------------------------------


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke the current refresh token and clear the cookie",
)
async def logout(
    db: DBSession,
    _: CurrentUser,
    payload: RefreshTokenRequest,
) -> MessageResponse:
    refresh_token = payload.refresh_token
    if refresh_token:
        await logout_user(db, refresh_token)
    return MessageResponse(message="Logged out successfully")


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser):
    return current_user


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
