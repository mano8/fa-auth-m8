"""Security regression: event-signing boot validator (F3 fail-closed).

auth-sdk-m8 1.0.0 introduces _enforce_event_signing_key: when
EVENT_SIGNING_ENABLED=true (the default), the service must fail closed at
boot if EVENT_SIGNING_KEY is not configured.

Tests:
- Negative path: Settings raises when EVENT_SIGNING_ENABLED=True and no key.
- Positive path: verified implicitly — the test module imports successfully,
  meaning the real .env (which now carries the key) satisfies the validator.
"""

import pytest
from pydantic import ValidationError

from auth_user_service.core.config import Settings

_MINIMAL_SETTINGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/user",
    "PROJECT_NAME": "TestApp",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost",
    "ACCESS_SECRET_KEY": "Aa1-test-access-secret-key-32chars!!",
    "REFRESH_SECRET_KEY": "Aa1-test-refresh-secret-key-32chars!",
    "DB_HOST": "localhost",
    "DB_PORT": 3306,
    "DB_DATABASE": "test_db",
    "DB_USER": "test_user",
    "DB_PASSWORD": "TestPass1@#!",
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_USER": "testuser",
    "REDIS_PASSWORD": "TestRedis1@#!",
    "FIRST_SUPERUSER": "admin@example.com",
    "FIRST_SUPERUSER_PASSWORD": "TestAdmin1@#!",
    "PRIVATE_API_SECRET": "Aa1-test-private-api-secret-32chars!!",
    "TOKENS_ENCRYPTION_KEY": "Aa1-test-encryption-key-32chars-here!",
    "TOKEN_STRICT_VALIDATION": False,
}


def test_event_signing_key_missing_raises():
    """Boot fails closed when EVENT_SIGNING_ENABLED=True and EVENT_SIGNING_KEY is None.

    Constructs Settings directly (bypassing dotenv via _env_file=None) so the
    real .env — which now supplies the key — cannot mask the failure. Pydantic
    wraps the model_validator error in ValidationError; assert it mentions
    EVENT_SIGNING_KEY so a missing-key scenario is unambiguous.
    """
    with pytest.raises((ValidationError, ValueError), match="EVENT_SIGNING_KEY"):
        Settings(
            _env_file=None,
            EVENT_SIGNING_ENABLED=True,
            EVENT_SIGNING_KEY=None,
            **_MINIMAL_SETTINGS,
        )
