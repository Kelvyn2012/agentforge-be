import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_verification_email(to_email: str, token: str) -> None:
    """
    Stub: in production, dispatch a real email via your provider.
    For now, the verification link is logged at INFO level.
    """
    url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    logger.info("VERIFY EMAIL (%s): %s", to_email, url)
