"""
Configuration settings for the FastAPI application.
This module loads environment settings securely and applies best practices.
"""

from pathlib import Path
from typing import Optional

from pydantic import EmailStr, Field, SecretStr, field_validator
from pydantic_settings import SettingsConfigDict
from auth_sdk_m8.utils.paths import find_dotenv
from auth_sdk_m8.core.config import CommonSettings
from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin
# pylint: disable=invalid-name, import-outside-toplevel


class Settings(ObservabilitySettingsMixin, CommonSettings):
    """Settings for the auth_user_service: adds only new fields."""

    # Override env file directory if necessary
    ENV_FILE_DIR = Path(__file__).resolve().parent

    # Pydantic v2 config must be a plain class attribute (no annotation)
    model_config = SettingsConfigDict(
        env_file=find_dotenv(ENV_FILE_DIR),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
    )

    # Extend validation lists
    required_fields = CommonSettings.required_fields
    secret_fields = CommonSettings.secret_fields + [
        "FIRST_SUPERUSER",
        "FIRST_SUPERUSER_PASSWORD",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "PRIVATE_API_SECRET",
        "SESSION_SECRET",
        "TOKENS_ENCRYPTION_KEY",
    ]
    passwords = CommonSettings.passwords + ["FIRST_SUPERUSER_PASSWORD"]
    secret_keys = CommonSettings.secret_keys + [
        "PRIVATE_API_SECRET",
        "SESSION_SECRET",
        "TOKENS_ENCRYPTION_KEY",
    ]
    TABLES_PREFIX: str = "auth"

    # Number of trusted reverse-proxy hops in front of this service.
    # Used to select the real client IP from X-Forwarded-For by taking
    # xff[-TRUSTED_PROXY_COUNT] (Nth entry from the right, 1-indexed, since
    # Traefik appends the peer IP). Must be >= 0.
    # Set to 1 when a single Traefik instance sits in front.
    TRUSTED_PROXY_COUNT: int = 1

    @field_validator("TRUSTED_PROXY_COUNT")
    @classmethod
    def _validate_proxy_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("TRUSTED_PROXY_COUNT must be >= 0")
        return v

    # Coarse per-source-IP login cap, shared across all accounts. Catches a
    # credential-spray that rotates the username every attempt (which evades
    # the per-email LOGIN_RATE_LIMIT_REQUESTS counter). Set higher than the
    # per-email limit to tolerate shared NAT / office egress IPs. Reuses the
    # per-email window (LOGIN_RATE_LIMIT_WINDOW_MINUTES). Defined here rather
    # than in the shared SDK so this hardening ships without an SDK release.
    LOGIN_IP_RATE_LIMIT_REQUESTS: int = Field(50, ge=1, le=100000)

    # ── Auth event stream (fa-auth SSE bridge) ───────────────────────────────
    # fa-auth bridges its own auth-state events (session revoked / user deleted)
    # to backend consumers over an authenticated SSE stream on the existing
    # private API. Push is a best-effort cache-eviction accelerator — the JTI
    # blacklist (jti-status) remains the revocation authority — so a disabled or
    # unreachable stream never changes correctness. Payloads are HMAC-signed with
    # the shared EVENT_SIGNING_KEY (reused, already boot-required).
    EVENT_STREAM_ENABLED: bool = True
    # Ring-buffer depth for Last-Event-ID resume. A reconnecting consumer whose
    # last id is still buffered replays exactly the missed events; once evicted
    # the server signals an unresumable gap and the consumer flushes its caches.
    EVENT_STREAM_BUFFER_SIZE: int = Field(256, ge=1, le=100000)
    # Heartbeat comment frame interval (seconds). Keeps the connection alive
    # through reverse proxies and lets a consumer detect a dead stream. Must be
    # comfortably below the consumer read timeout.
    EVENT_STREAM_HEARTBEAT_SECONDS: float = Field(15.0, gt=0, le=300)
    # Per-connection outbound queue depth before a slow consumer is disconnected
    # (it reconnects and resumes/flushes). Never blocks the emitting request.
    EVENT_STREAM_MAX_QUEUE: int = Field(64, ge=1, le=100000)

    # API key rate limiting defaults (0 = disabled for that period)
    API_KEY_STRICT_RATE_LIMIT: bool = False
    API_KEY_DEFAULT_LIMIT_MINUTE: int = 60
    API_KEY_DEFAULT_LIMIT_HOUR: int = 1_000
    API_KEY_DEFAULT_LIMIT_DAY: int = 10_000
    API_KEY_DEFAULT_LIMIT_MONTH: int = 200_000
    API_KEY_MAX_PER_USER: int = 10

    # Declare only service-specific fields
    FIRST_SUPERUSER: EmailStr
    FIRST_SUPERUSER_PASSWORD: SecretStr
    GOOGLE_CLIENT_ID: Optional[SecretStr] = None
    GOOGLE_CLIENT_SECRET: Optional[SecretStr] = None
    # Fixed backend callback URI — must match Google Console exactly.
    # Never auto-generated from request host to prevent host-spoofing.
    GOOGLE_OAUTH_REDIRECT_URI: str = ""
    PRIVATE_API_SECRET: SecretStr
    # Dedicated signing key for the Starlette session cookie. Kept separate
    # from TOKENS_ENCRYPTION_KEY (key separation): rotating the session key
    # must not invalidate encrypted external tokens, and vice versa.
    SESSION_SECRET: SecretStr
    TOKENS_ENCRYPTION_KEY: SecretStr


try:
    settings = Settings()
except Exception as e:
    # Raise with a clear error message if validation fails.
    raise RuntimeError(f"Configuration validation error:\n {str(e)}") from e

if __name__ == "__main__":
    # For debugging, print out public settings without exposing secrets.
    public_settings = settings.model_dump()
    for field in settings.secret_fields:
        public_settings.pop(field, None)
    print(public_settings)
