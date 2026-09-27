"""A4 (ACCT-G5, D-c) — every password mutation revokes, and only PASSWORD
accounts have one.

Security invariant: *password mutation revokes everything.* After a
self-service change or an admin set, every session of the account — the
caller's included — fails on each validation path: ``jti-status``
(DB-authoritative), refresh (lineage check), and the access-token /
consumer-cache accelerators (durable blacklist + v2 publish effects). A refused
mutation writes nothing. A GOOGLE account has no password to change or set,
whatever ``provider`` the client claims. These run the real services against a
database session.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlmodel import Session, select

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    RevocationOutbox,
)
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.routes.users import update_current_user
from auth_user_service.services import password as password_module
from auth_user_service.services.auth import AuthController
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.password import (
    IncorrectCurrentPassword,
    PasswordController,
    PasswordNotAllowed,
    PasswordUnchanged,
)
from auth_user_service.services.role_admin import change_user_authorization
from tests.conftest import TEST_PASSWORD

pytestmark = pytest.mark.security

_NEW_PASSWORD = "Rotated!Passw0rd"


def _plant_session(db_session: Session, user: User) -> str:
    now = datetime.now(timezone.utc)
    jti = uuid.uuid4().hex
    db_session.add(
        ClientSession(
            user_id=user.id,
            provider=user.provider,
            jwt_jti=jti,
            refresh_token_hash="f" * 64,
            jwt_expires_at=now + timedelta(hours=1),
            refresh_expires_at=now + timedelta(days=1),
            auth_generation=user.auth_generation,
        )
    )
    db_session.commit()
    return jti


def _assert_session_dead(db_session: Session, user: User, jti: str) -> None:
    db_session.refresh(user)
    assert not GenerationController.decide_jti_status(db_session, jti, user.id).active
    assert not AuthController.refresh_lineage_is_current(
        session=db_session, user=user, session_jti=jti
    )
    effects = db_session.exec(
        select(RevocationOutbox).where(RevocationOutbox.user_id == user.id)
    ).all()
    blacklisted = {
        row.payload["jti"] for row in effects if row.effect_type == EFFECT_BLACKLIST
    }
    published = {
        row.auth_generation for row in effects if row.effect_type == EFFECT_PUBLISH
    }
    assert jti in blacklisted
    assert user.auth_generation in published


def _assert_session_alive(db_session: Session, user: User, jti: str) -> None:
    assert GenerationController.decide_jti_status(db_session, jti, user.id).active


# ── self-service change ───────────────────────────────────────────────────────


def test_change_revokes_every_session_including_the_callers(
    db_session, sample_user, caplog
) -> None:
    current = _plant_session(db_session, sample_user)
    other = _plant_session(db_session, sample_user)
    generation = sample_user.auth_generation

    with caplog.at_level("INFO", logger=password_module.logger.name):
        result = PasswordController.change_own_password(
            db_session,
            sample_user,
            current_password=TEST_PASSWORD,
            new_password=_NEW_PASSWORD,
        )

    assert result.auth_generation == generation + 1
    _assert_session_dead(db_session, sample_user, current)
    _assert_session_dead(db_session, sample_user, other)
    assert SecurityHelper.verify_password(_NEW_PASSWORD, sample_user.hashed_password)
    assert not SecurityHelper.verify_password(
        TEST_PASSWORD, sample_user.hashed_password
    )
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert f"event=password.changed user_id={sample_user.id} actor=self" in logged
    assert _NEW_PASSWORD not in logged
    assert TEST_PASSWORD not in logged
    assert str(sample_user.hashed_password) not in logged


def test_old_password_no_longer_authenticates(db_session, sample_user) -> None:
    PasswordController.change_own_password(
        db_session,
        sample_user,
        current_password=TEST_PASSWORD,
        new_password=_NEW_PASSWORD,
    )

    assert (
        AuthController.authenticate(
            session=db_session, email=sample_user.email, password=TEST_PASSWORD
        )
        is None
    )
    assert (
        AuthController.authenticate(
            session=db_session, email=sample_user.email, password=_NEW_PASSWORD
        )
        is not None
    )


@pytest.mark.parametrize(
    "current,new,error",
    [
        ("Wrong!Passw0rd", _NEW_PASSWORD, IncorrectCurrentPassword),
        (TEST_PASSWORD, TEST_PASSWORD, PasswordUnchanged),
    ],
)
def test_refused_change_writes_nothing(
    db_session, sample_user, current, new, error
) -> None:
    jti = _plant_session(db_session, sample_user)
    old_hash, generation = sample_user.hashed_password, sample_user.auth_generation

    with pytest.raises(error):
        PasswordController.change_own_password(
            db_session, sample_user, current_password=current, new_password=new
        )

    db_session.refresh(sample_user)
    assert sample_user.hashed_password == old_hash
    assert sample_user.auth_generation == generation
    _assert_session_alive(db_session, sample_user, jti)


def test_google_account_has_no_password_to_change(db_session, google_user) -> None:
    jti = _plant_session(db_session, google_user)
    generation = google_user.auth_generation

    with pytest.raises(PasswordNotAllowed):
        PasswordController.change_own_password(
            db_session,
            google_user,
            current_password=TEST_PASSWORD,
            new_password=_NEW_PASSWORD,
        )

    db_session.refresh(google_user)
    assert google_user.hashed_password is None
    assert google_user.auth_generation == generation
    _assert_session_alive(db_session, google_user, jti)


def test_password_account_without_a_hash_is_refused(db_session) -> None:
    """Constant-work check: no stored hash is a failed check, never a pass."""
    user = User(
        id=uuid.uuid4(),
        email=f"nohash_{uuid.uuid4().hex[:10]}@example.com",
        full_name="No Hash",
        hashed_password=None,
        provider=AuthProviderType.PASSWORD,
        is_active=True,
        email_verified=True,
        is_superuser=False,
        role=RoleType.USER,
    )
    db_session.add(user)
    db_session.commit()

    with pytest.raises(IncorrectCurrentPassword):
        PasswordController.change_own_password(
            db_session,
            user,
            current_password=TEST_PASSWORD,
            new_password=_NEW_PASSWORD,
        )
    db_session.refresh(user)
    assert user.hashed_password is None


# ── admin set ─────────────────────────────────────────────────────────────────


def test_admin_set_revokes_and_is_audited(
    db_session, sample_user, superuser, caplog
) -> None:
    jti = _plant_session(db_session, sample_user)
    generation = sample_user.auth_generation

    with caplog.at_level("INFO", logger=password_module.logger.name):
        result = change_user_authorization(
            session=db_session,
            actor_id=superuser.id,
            actor_role=RoleType.SUPERADMIN,
            db_user=sample_user,
            user_in=UserUpdate(password=_NEW_PASSWORD),
        )

    assert result.revocation_enqueued is True
    assert result.auth_generation == generation + 1
    _assert_session_dead(db_session, sample_user, jti)
    assert SecurityHelper.verify_password(_NEW_PASSWORD, sample_user.hashed_password)
    audit = db_session.exec(
        select(PrivilegedActionAudit).where(
            PrivilegedActionAudit.row_pk == str(sample_user.id),
            PrivilegedActionAudit.action == AuditAction.EDIT,
        )
    ).all()
    assert audit
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert (
        f"event=password.changed user_id={sample_user.id} actor=admin "
        f"actor_id={superuser.id}"
    ) in logged
    assert _NEW_PASSWORD not in logged


def test_admin_set_bumps_once_with_other_transitions(
    db_session, sample_user, superuser
) -> None:
    generation = sample_user.auth_generation

    result = change_user_authorization(
        session=db_session,
        actor_id=superuser.id,
        actor_role=RoleType.SUPERADMIN,
        db_user=sample_user,
        user_in=UserUpdate(
            password=_NEW_PASSWORD,
            email=f"moved_{uuid.uuid4().hex[:10]}@example.com",
        ),
    )

    assert result.auth_generation == generation + 1


@pytest.mark.parametrize("claimed", [None, AuthProviderType.PASSWORD])
def test_admin_cannot_give_a_google_account_a_password(
    db_session, google_user, superuser, claimed
) -> None:
    """The stored provider decides; a client-claimed PASSWORD changes nothing."""
    jti = _plant_session(db_session, google_user)
    generation = google_user.auth_generation

    with pytest.raises(PasswordNotAllowed):
        change_user_authorization(
            session=db_session,
            actor_id=superuser.id,
            actor_role=RoleType.SUPERADMIN,
            db_user=google_user,
            user_in=UserUpdate(password=_NEW_PASSWORD, provider=claimed),
        )
    db_session.rollback()

    db_session.refresh(google_user)
    assert google_user.hashed_password is None
    assert google_user.auth_generation == generation
    _assert_session_alive(db_session, google_user, jti)


def test_admin_route_maps_google_refusal_to_403(
    db_session, google_user, superuser
) -> None:
    with pytest.raises(HTTPException) as exc:
        update_current_user(
            session=db_session,
            current_user=superuser,
            user_id=google_user.id,
            user_in=UserUpdate(password=_NEW_PASSWORD),
        )
    assert exc.value.status_code == 403
    db_session.rollback()
    db_session.refresh(google_user)
    assert google_user.hashed_password is None


def test_admin_update_without_password_keeps_the_hash(
    db_session, sample_user, superuser
) -> None:
    old_hash = sample_user.hashed_password
    jti = _plant_session(db_session, sample_user)

    result = change_user_authorization(
        session=db_session,
        actor_id=superuser.id,
        actor_role=RoleType.SUPERADMIN,
        db_user=sample_user,
        user_in=UserUpdate(full_name="Profile Only"),
    )

    assert result.revocation_enqueued is False
    assert result.user.hashed_password == old_hash
    _assert_session_alive(db_session, sample_user, jti)
