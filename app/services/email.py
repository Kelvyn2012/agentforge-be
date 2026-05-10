import logging

logger = logging.getLogger(__name__)


def send_verification_email(_to_email: str, _token: str) -> None:
    """
    Stub: in production, dispatch a real email via your provider.
    Keep token delivery behind this boundary so endpoints never log secrets.
    """
    logger.info("Verification email queued")


def send_password_reset_email(_to_email: str, reset_url: str) -> None:
    """
    Stub: swap this body for a real provider (SendGrid, Resend, SES, etc.) when ready.
    """
    logger.info("Password reset email queued")
    print(f"[DEV] Password reset link: {reset_url}", flush=True)
