"""S1A (N3, N17) — an email change needs re-authentication and revokes.

Security invariant: *email cannot be squatted.* A GOOGLE account cannot change
its email; a PASSWORD account must present ``current_password``; any applied
change — self-service or admin — clears ``email_verified``, bumps
``auth_generation``, revokes every session with the durable outbox effects, and
is audited. These run the real service against a database session.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session, select

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.db_models.outbox import EFFECT_BLACKLIST, RevocationOutbox
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User, UserUpdate, UserUpdateMe
from auth_user_service.services import profile as profile_module
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.profile import (
    CurrentPasswordRequired,
    EmailAlreadyInUse,
    EmailChangeNotAllowed,
    IncorrectCurrentPassword,
    ProfileController,
)
from auth_user_service.services.role_admin import change_user_authorization
from tests.conftest import TEST_PASSWORD

pytestmark = pytest.mark.security


def _new_email() -> str:
    return f"moved_{uuid.uuid4().hex[:10]}@example.com"


def _plant_session(db_session: Session, user: User) -> str:
    now = datetime.now(timezone.utc)
    jti = uuid.uuid4().hex
    db_session.add(
        ClientSession(
            user_id=user.id,
            provider=user.provider,
            jwt_jti=jti,
            refresh_token_hash="e" * 64,
            jwt_expires_at=now + timedelta(hours=1),
            refresh_expires_at=now + timedelta(days=1),
            auth_generation=user.auth_generation,
        )
    )
    db_session.commit()
    return jti


def _assert_revoked(db_session: Session, user: User, jti: str) -> None:
    assert not GenerationController.decide_jti_status(db_session, jti, user.id).active
    blacklisted = {
        row.payload["jti"]
        for row in db_session.exec(
            select(RevocationOutbox).where(RevocationOutbox.user_id == user.id)
        )
        if row.effect_type == EFFECT_BLACKLIST
    }
    assert jti in blacklisted


# ── self-service ──────────────────────────────────────────────────────────────


def test_password_account_change_clears_verification_and_revokes(
    db_session, sample_user, caplog
) -> None:
    jti = _plant_session(db_session, sample_user)
    generation, new_email = sample_user.auth_generation, _new_email()

    with caplog.at_level("INFO", logger=profile_module.logger.name):
        result = ProfileController.update_me(
            db_session,
            sample_user,
            UserUpdateMe(email=new_email, current_password=TEST_PASSWORD),
        )

    assert result.email_changed is True
    assert result.user.email == new_email
    assert result.user.email_verified is False
    assert result.user.auth_generation == generation + 1
    _assert_revoked(db_session, sample_user, jti)
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert f"event=profile.email_changed user_id={sample_user.id}" in logged
    assert new_email not in logged


@pytest.mark.parametrize(
    "password,error",
    [(None, CurrentPasswordRequired), ("wrong-password", IncorrectCurrentPassword)],
)
def test_password_account_without_the_password_changes_nothing(
    db_session, sample_user, password, error
) -> None:
    jti = _plant_session(db_session, sample_user)
    email, generation = sample_user.email, sample_user.auth_generation

    with pytest.raises(error):
        ProfileController.update_me(
            db_session,
            sample_user,
            UserUpdateMe(email=_new_email(), current_password=password),
        )

    db_session.refresh(sample_user)
    assert sample_user.email == email
    assert sample_user.email_verified is True
    assert sample_user.auth_generation == generation
    assert GenerationController.decide_jti_status(
        db_session, jti, sample_user.id
    ).active


def test_google_account_cannot_squat_an_address(db_session, google_user) -> None:
    email = google_user.email
    with pytest.raises(EmailChangeNotAllowed):
        ProfileController.update_me(
            db_session,
            google_user,
            UserUpdateMe(email=_new_email(), current_password=TEST_PASSWORD),
        )
    db_session.refresh(google_user)
    assert google_user.email == email


def test_address_in_use_is_refused(db_session, sample_user, superuser) -> None:
    with pytest.raises(EmailAlreadyInUse):
        ProfileController.update_me(
            db_session,
            sample_user,
            UserUpdateMe(email=superuser.email, current_password=TEST_PASSWORD),
        )


def test_password_account_without_a_hash_is_refused(db_session) -> None:
    """Constant-work check: no stored hash is a failed check, never a pass."""
    user = User(
        id=uuid.uuid4(),
        email=_new_email(),
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
        ProfileController.update_me(
            db_session,
            user,
            UserUpdateMe(email=_new_email(), current_password=TEST_PASSWORD),
        )


# ── admin ─────────────────────────────────────────────────────────────────────


def test_admin_email_change_clears_verification_and_revokes(
    db_session, sample_user, superuser
) -> None:
    jti = _plant_session(db_session, sample_user)
    generation = sample_user.auth_generation

    result = change_user_authorization(
        session=db_session,
        actor_id=superuser.id,
        actor_role=RoleType.SUPERADMIN,
        db_user=sample_user,
        user_in=UserUpdate(email=_new_email()),
    )

    assert result.revocation_enqueued is True
    assert result.user.email_verified is False
    assert result.auth_generation == generation + 1
    _assert_revoked(db_session, sample_user, jti)


def test_admin_update_without_email_change_revokes_nothing(
    db_session, sample_user, superuser
) -> None:
    jti = _plant_session(db_session, sample_user)

    result = change_user_authorization(
        session=db_session,
        actor_id=superuser.id,
        actor_role=RoleType.SUPERADMIN,
        db_user=sample_user,
        user_in=UserUpdate(email=sample_user.email, full_name="Same Address"),
    )

    assert result.revocation_enqueued is False
    assert result.user.email_verified is True
    assert GenerationController.decide_jti_status(
        db_session, jti, sample_user.id
    ).active
