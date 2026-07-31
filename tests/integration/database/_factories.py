"""Row factories for the Layer B matrix (``TEST-DB-01``).

Two flavours, deliberately kept apart:

* **ORM factories** exercise the mapped models the service itself uses, so a
  mapping that only works against the SQLite surrogate fails here.
* **Raw-SQL factories** bypass the ORM entirely — the only way to prove an
  engine-enforced constraint rejects a row, since the ORM/`SQLModel` validators
  would refuse to build the invalid object in the first place (the constraint
  evidence separation required by 50).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

import sqlalchemy as sa
from sqlmodel import Session

from auth_sdk_m8.schemas.base import ApiKeyAccessMode, AuthProviderType, RoleType

from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience
from auth_user_service.db_models.sessions import ClientSession, ClientSessionCreate
from auth_user_service.db_models.users import User
from auth_user_service.services.client_sessions import SessionController


def jti(label: str) -> str:
    """A readable JTI that satisfies ``ClientSessionCreate``'s 16-char minimum.

    Short literals like ``"logout"`` are rejected by the schema, so every test
    JTI is built here rather than padded ad hoc at each call site.
    """
    return f"layerb-{label}".ljust(16, "-")


def naive_utc(moment: Optional[datetime] = None) -> datetime:
    """UTC timestamp without tzinfo — the shape every DateTime column stores."""
    return (moment or datetime.now(timezone.utc)).replace(tzinfo=None)


def make_user(
    session: Session,
    *,
    role: RoleType = RoleType.USER,
    is_superuser: bool = False,
    is_active: bool = True,
    auth_generation: int = 1,
) -> User:
    """Persist a canonical user row through the ORM."""
    user = User(
        id=uuid.uuid4(),
        email=f"it_{uuid.uuid4().hex[:12]}@example.com",
        full_name="Layer B User",
        hashed_password="x" * 60,
        provider=AuthProviderType.PASSWORD,
        is_active=is_active,
        email_verified=True,
        is_superuser=is_superuser,
        role=role,
        auth_generation=auth_generation,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def make_superuser(session: Session, **kwargs: object) -> User:
    """Persist an active canonical superuser (the last-superuser set member)."""
    return make_user(
        session,
        role=RoleType.SUPERADMIN,
        is_superuser=True,
        **kwargs,  # type: ignore[arg-type]
    )


def issue_session(
    session: Session, user: User, *, jti: Optional[str] = None
) -> ClientSession:
    """Issue a session through the real issuance path (stamps the generation)."""
    now = naive_utc()
    return SessionController.create_client_session(
        session=session,
        current_user=user,
        session_data=ClientSessionCreate(
            jwt_jti=jti or str(uuid.uuid4()),
            refresh_token_hash="r" * 64,
            jwt_expires_at=now + timedelta(hours=1),
            refresh_expires_at=now + timedelta(days=7),
        ),
    )


def make_api_key(
    session: Session,
    user: User,
    *,
    access_mode: ApiKeyAccessMode = ApiKeyAccessMode.READ_ONLY,
    revoked: bool = False,
    expires_at: Optional[datetime] = None,
    audiences: tuple[str, ...] = (),
    updated_at: Optional[datetime] = None,
) -> ApiKey:
    """Persist an API key (optionally with audience bindings) through the ORM."""
    key = ApiKey(
        id=uuid.uuid4(),
        name=f"key-{uuid.uuid4().hex[:8]}",
        key_hash=uuid.uuid4().hex * 2,
        user_id=user.id,
        access_mode=access_mode,
        revoked=revoked,
        expires_at=expires_at,
    )
    session.add(key)
    session.commit()
    for audience in audiences:
        session.add(
            ApiKeyAudience(
                api_key_id=key.id, audience_id=audience, created_at=naive_utc()
            )
        )
    if audiences:
        session.commit()
    if updated_at is not None:
        # ``updated_at`` carries ``onupdate=CURRENT_TIMESTAMP``, so the dead-key
        # purge's revocation clock can only be back-dated with raw SQL.
        session.execute(
            sa.text("UPDATE auth_api_key SET updated_at = :ts WHERE id = :id"),
            {
                "ts": naive_utc(updated_at),
                "id": uuid_literal(session.get_bind(), key.id),
            },
        )
        session.commit()
    session.refresh(key)
    return key


# ── raw-SQL insertion (constraint evidence — never through the ORM) ───────────


def uuid_literal(bind: Union[sa.Engine, sa.Connection], value: uuid.UUID) -> str:
    """Bind form of a UUID for this dialect's ``id`` column representation.

    PostgreSQL stores a native ``uuid``; MySQL/MariaDB store ``CHAR(32)``
    (hyphen-free), so a raw insert must supply the matching text form.
    """
    return str(value) if bind.dialect.name == "postgresql" else value.hex


def raw_insert_user(
    engine: sa.Engine,
    *,
    role: str,
    is_superuser: bool,
    user_id: Optional[uuid.UUID] = None,
    auth_generation: int = 1,
    connection: Optional[sa.Connection] = None,
) -> uuid.UUID:
    """Insert a user row with raw SQL, bypassing every ORM/model validator."""
    identifier = user_id or uuid.uuid4()
    statement = sa.text(
        "INSERT INTO auth_user (created_at, updated_at, provider, email, "
        "is_active, email_verified, is_superuser, role, auth_generation, id) "
        "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', :email, "
        "true, true, :is_superuser, :role, :auth_generation, :id)"
    )
    params = {
        "email": f"raw_{identifier.hex[:12]}@example.com",
        "is_superuser": is_superuser,
        "role": role,
        "auth_generation": auth_generation,
        "id": uuid_literal(engine, identifier),
    }
    if connection is not None:
        connection.execute(statement, params)
    else:
        with engine.begin() as conn:
            conn.execute(statement, params)
    return identifier
