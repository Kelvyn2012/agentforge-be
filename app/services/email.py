import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_verification_email(_to_email: str, token: str) -> None:
    """
    Stub: in production, dispatch a real email via your provider.
    """
    logger.info("Verification email queued")
    verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    print(f"[DEV] Verify email link: {verification_url}", flush=True)


def send_password_reset_email(_to_email: str, reset_url: str) -> None:
    """
    Stub: swap this body for a real provider (SendGrid, Resend, SES, etc.) when ready.
    """
    logger.info("Password reset email queued")
    print(f"[DEV] Password reset link: {reset_url}", flush=True)
