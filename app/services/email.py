import logging

logger = logging.getLogger(__name__)


def send_verification_email(to_email: str, _token: str) -> None:
    """
    Stub: in production, dispatch a real email via your provider.
    Keep token delivery behind this boundary so endpoints never log secrets.
    """
    logger.info("Verification email queued for %s", to_email)
