"""
Shared pytest fixtures for the fa-auth-m8 test suite.
"""

import os

# ── 1. Seed required env vars BEFORE any auth_user_service import ─────────────
# The issuer Settings validates a full secret set at import time, and
# CommonSettings resolves ``env_file`` via ``find_dotenv()`` which *raises* when
# no ``.env`` exists (e.g. CI). Seed hermetic test values here (``setdefault`` →
# a real exported env still wins) and stub ``find_dotenv`` below so a local
# developer ``.env`` is never auto-loaded under test. Non-secret values mirror
# the example stacks; secrets are obvious throwaways that satisfy the strength
# validator (8+ chars, upper/lower/digit/special). Mirrors the media-service-m8
# and fastapi-m8 conftest bootstrap.
_TEST_ENV = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "PROJECT_NAME": "fa-auth-m8",
    "STACK_NAME": "fa-auth-m8",
    "API_PREFIX": "/user",
    "BACKEND_HOST": "http://localhost:8000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost:8000,http://localhost:5173",
    "SELECTED_DB": "Mysql",
    "DB_HOST": "localhost",
    "DB_PORT": "3306",
    "DB_DATABASE": "test_db",
    "DB_USER": "test_user",
    "DB_PASSWORD": "TestDb!Pass1secure",
    "REDIS_HOST": "localhost",
    "REDIS_PORT": "6379",
    "REDIS_USER": "appuser",
    "REDIS_PASSWORD": "TestRedis!Pass1secure",
    "ACCESS_SECRET_KEY": "TestAccess!Key4UnitTests_onlyXYZ0987",
    "REFRESH_SECRET_KEY": "TestRefresh!Key4UnitTests_onlyABC1234",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "REFRESH_TOKEN_ALGORITHM": "HS256",
    "TOKEN_STRICT_VALIDATION": "false",
    "EVENT_SIGNING_KEY": "TestEvent!Signing4UnitTests_only5678",
    "FIRST_SUPERUSER": "admin@example.com",
    "FIRST_SUPERUSER_PASSWORD": "TestSuper!Pass1secure",
    "PRIVATE_API_SECRET": "TestPrivate!ApiSecret1secureXYZ098",
    "SESSION_SECRET": "TestSession!Secret1secureKeyABC123",
    "TOKENS_ENCRYPTION_KEY": "TestTokens!EncKey1secureKeyABC1234",
    "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "TestGoogle!Secret1secureKeyXYZ098",
}
for _k, _v in _TEST_ENV.items():
    os.environ.setdefault(_k, _v)

# ── 2. Stop the local developer .env from being auto-loaded under test ────────
#       (must happen BEFORE the first auth_user_service import).
import auth_sdk_m8.utils.paths as _paths_mod  # noqa: E402

_real_find_dotenv = _paths_mod.find_dotenv
_paths_mod.find_dotenv = lambda *_a, **_kw: ""

import sqlite3  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

# SQLite does not natively support uuid.UUID — register an adapter so that
# SQLAlchemy can bind UUID values when using the in-memory test engine.
sqlite3.register_adapter(uuid.UUID, str)
sqlite3.register_converter("CHAR", lambda b: b.decode("utf-8"))

from auth_user_service.core.security import SecurityHelper  # noqa: E402
from auth_user_service.db_models.api_keys import ApiKey, RateLimit  # noqa: E402, F401
from auth_user_service.db_models.sessions import ClientSession  # noqa: E402
from auth_user_service.db_models.users import User  # noqa: E402
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType  # noqa: E402

# Restore find_dotenv after all imports are done (good hygiene).
_paths_mod.find_dotenv = _real_find_dotenv

TEST_PASSWORD = "testpassword123"


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={
            "check_same_thread": False,
            "detect_types": sqlite3.PARSE_DECLTYPES,
        },
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    with Session(db_engine) as session:
        yield session
        session.rollback()


@pytest.fixture
def mock_redis():
    return MagicMock()


@pytest.fixture
def sample_user(db_session):
    user = User(
        id=uuid.uuid4(),
        email=f"user_{uuid.uuid4().hex[:8]}@example.com",
        full_name="Test User",
        hashed_password=SecurityHelper.get_password_hash(TEST_PASSWORD),
        provider=AuthProviderType.PASSWORD,
        is_active=True,
        email_verified=True,
        is_superuser=False,
        role=RoleType.USER,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def inactive_user(db_session):
    user = User(
        id=uuid.uuid4(),
        email=f"inactive_{uuid.uuid4().hex[:8]}@example.com",
        full_name="Inactive User",
        hashed_password=SecurityHelper.get_password_hash(TEST_PASSWORD),
        provider=AuthProviderType.PASSWORD,
        is_active=False,
        email_verified=False,
        is_superuser=False,
        role=RoleType.USER,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def superuser(db_session):
    user = User(
        id=uuid.uuid4(),
        email=f"superuser_{uuid.uuid4().hex[:8]}@example.com",
        full_name="Super User",
        hashed_password=SecurityHelper.get_password_hash(TEST_PASSWORD),
        provider=AuthProviderType.PASSWORD,
        is_active=True,
        email_verified=True,
        is_superuser=True,
        role=RoleType.USER,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def google_user(db_session):
    user = User(
        id=uuid.uuid4(),
        email=f"google_{uuid.uuid4().hex[:8]}@example.com",
        full_name="Google User",
        oauth_user_id=f"google_{uuid.uuid4().hex}",
        provider=AuthProviderType.GOOGLE,
        is_active=True,
        email_verified=True,
        is_superuser=False,
        role=RoleType.USER,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_client_session(db_session, sample_user):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    client_session = ClientSession(
        id=str(uuid.uuid4()),
        user_id=sample_user.id,
        provider=AuthProviderType.PASSWORD,
        jwt_jti=str(uuid.uuid4()),
        refresh_token_hash="a" * 64,
        jwt_expires_at=now + timedelta(hours=1),
        refresh_expires_at=now + timedelta(days=7),
        revoked=False,
    )
    db_session.add(client_session)
    db_session.commit()
    db_session.refresh(client_session)
    return client_session


@pytest.fixture
def expired_client_session(db_session, sample_user):
    past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=10)
    client_session = ClientSession(
        id=str(uuid.uuid4()),
        user_id=sample_user.id,
        provider=AuthProviderType.PASSWORD,
        jwt_jti=str(uuid.uuid4()),
        refresh_token_hash="b" * 64,
        jwt_expires_at=past,
        refresh_expires_at=past,
        revoked=False,
    )
    db_session.add(client_session)
    db_session.commit()
    db_session.refresh(client_session)
    return client_session


_UNIT_DIRS = {"core", "services", "schemas", "db_models", "utils"}


def pytest_collection_modifyitems(config, items: list) -> None:
    for item in items:
        if item.fspath.dirpath().basename in _UNIT_DIRS:
            item.add_marker(pytest.mark.unit)
