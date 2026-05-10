from functools import lru_cache
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from pydantic import PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ASYNCPG_UNSUPPORTED_PARAMS = {"sslmode", "channel_binding"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "agentforge-be"
    API_V1_PREFIX: str = "/api/v1"

    DATABASE_URL: PostgresDsn
    DB_USE_SSL: bool = False

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def strip_asyncpg_unsupported_params(cls, v: str) -> str:
        parsed = urlparse(str(v))
        params = {
            k: vals
            for k, vals in parse_qs(parsed.query).items()
            if k not in _ASYNCPG_UNSUPPORTED_PARAMS
        }
        clean_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=clean_query))

    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 60
    VERIFICATION_TOKEN_TTL_HOURS: int = 24
    REFRESH_TOKEN_TTL_DAYS: int = 7
    TRUSTED_PROXIES: str = ""
    COOKIE_SECURE: bool = False

    FRONTEND_URL: str = "http://localhost:3000"

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = ""
    GOOGLE_AUTH_URL: str = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL: str = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL: str = "https://openidconnect.googleapis.com/v1/userinfo"
    GOOGLE_SCOPES: str = "openid email profile"

    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
