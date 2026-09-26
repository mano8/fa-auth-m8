"""S1A (N16) — evict the sessions obtained through the implicit Google link.

Security invariant: *nobody stays inside through the removed link.* After a
remediation run, every session of a reported account fails on each validation
path — ``jti-status`` (DB-authoritative), refresh (lineage check), and the
access-token / consumer-cache accelerators (durable blacklist + v2 publish
effects) — and a repeat run is a no-op.

The database is shared across the session, so assertions are about the rows
each test plants, never about the whole result.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session, select

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    RevocationOutbox,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.services.auth import AuthController
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.google_link_remediation import (
    GoogleLinkRemediationController,
    RemediationResult,
    RemediationScope,
)

pytestmark = pytest.mark.security


def _plant_session(db_session: Session, user: User, *, google: bool) -> str:
    """Plant a current-generation session; *google* marks the implicit link."""
    now = datetime.now(timezone.utc)
    jti = uuid.uuid4().hex
    db_session.add(
        ClientSession(
            user_id=user.id,
            provider=AuthProviderType.PASSWORD,
            jwt_jti=jti,
            refresh_token_hash="c" * 64,
            jwt_expires_at=now + timedelta(hours=1),
            refresh_expires_at=now + timedelta(days=1),
            auth_generation=user.auth_generation,
            external_access_token="enc-access" if google else None,
            external_refresh_token="enc-refresh" if google else None,
        )
    )
    db_session.commit()
    return jti


def _assert_session_dead(db_session: Session, user: User, jti: str) -> None:
    db_session.refresh(user)
    decision = GenerationController.decide_jti_status(db_session, jti, user.id)
    assert decision.active is False
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


def test_reported_account_loses_every_session_path(db_session, sample_user) -> None:
    jti = _plant_session(db_session, sample_user, google=True)
    assert GenerationController.decide_jti_status(
        db_session, jti, sample_user.id
    ).active
    generation = sample_user.auth_generation

    result = GoogleLinkRemediationController.run(db_session, RemediationScope.REPORTED)

    assert sample_user.id in result.user_ids
    assert result.revoked_session_count >= 1
    _assert_session_dead(db_session, sample_user, jti)
    assert sample_user.auth_generation == generation + 1


def test_superadmin_reached_through_the_link_is_evicted(db_session, superuser) -> None:
    jti = _plant_session(db_session, superuser, google=True)

    GoogleLinkRemediationController.run(db_session, RemediationScope.REPORTED)

    _assert_session_dead(db_session, superuser, jti)


def test_reported_scope_leaves_unreported_accounts_alone(
    db_session, sample_user, inactive_user
) -> None:
    _plant_session(db_session, inactive_user, google=True)
    plain = _plant_session(db_session, sample_user, google=False)
    generation = sample_user.auth_generation

    result = GoogleLinkRemediationController.run(db_session, RemediationScope.REPORTED)

    assert inactive_user.id in result.user_ids
    assert sample_user.id not in result.user_ids
    db_session.refresh(sample_user)
    assert sample_user.auth_generation == generation
    assert GenerationController.decide_jti_status(
        db_session, plain, sample_user.id
    ).active


def test_repeat_run_is_a_no_op(db_session, sample_user) -> None:
    _plant_session(db_session, sample_user, google=True)
    GoogleLinkRemediationController.run(db_session, RemediationScope.REPORTED)
    db_session.refresh(sample_user)
    generation = sample_user.auth_generation

    again = GoogleLinkRemediationController.run(db_session, RemediationScope.REPORTED)

    assert sample_user.id not in again.user_ids
    db_session.refresh(sample_user)
    assert sample_user.auth_generation == generation


def test_all_sessions_scope_revokes_unreported_accounts_too(
    db_session, sample_user, google_user
) -> None:
    plain = _plant_session(db_session, sample_user, google=False)
    google = _plant_session(db_session, google_user, google=True)

    result = GoogleLinkRemediationController.run(
        db_session, RemediationScope.ALL_SESSIONS
    )

    assert {sample_user.id, google_user.id} <= set(result.user_ids)
    _assert_session_dead(db_session, sample_user, plain)
    _assert_session_dead(db_session, google_user, google)
    again = GoogleLinkRemediationController.run(
        db_session, RemediationScope.ALL_SESSIONS
    )
    assert again.user_ids == ()


def test_result_counts() -> None:
    uid = uuid.uuid4()
    result = RemediationResult(
        scope=RemediationScope.REPORTED, user_ids=(uid,), revoked_session_count=2
    )
    assert result.account_count == 1
