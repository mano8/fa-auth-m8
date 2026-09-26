"""Unit tests for the read-only implicit-Google-link report (S1).

The database is shared across the session, so assertions are about the rows
each test plants, never about the whole result.
"""

import uuid
from datetime import datetime, timedelta, timezone

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.services.google_link_report import (
    GoogleLinkReport,
    GoogleLinkReportController,
)


def _plant_session(
    db_session,
    user_id: uuid.UUID,
    *,
    provider: AuthProviderType = AuthProviderType.PASSWORD,
    external: bool = False,
    revoked: bool = False,
) -> None:
    now = datetime.now(timezone.utc)
    db_session.add(
        ClientSession(
            user_id=user_id,
            provider=provider,
            jwt_jti=uuid.uuid4().hex,
            refresh_token_hash="b" * 64,
            jwt_expires_at=now + timedelta(hours=1),
            refresh_expires_at=now + timedelta(days=1),
            revoked=revoked,
            external_access_token="enc-access" if external else None,
            external_refresh_token="enc-refresh" if external else None,
        )
    )
    db_session.commit()


def test_password_account_with_google_tokens_is_listed(db_session, sample_user):
    _plant_session(db_session, sample_user.id, external=True)

    report = GoogleLinkReportController.run(db_session)

    assert sample_user.id in report.user_ids
    assert sample_user.id not in report.superadmin_ids
    assert not report.clean


def test_google_provider_session_on_password_account_is_listed(db_session, sample_user):
    _plant_session(
        db_session, sample_user.id, provider=AuthProviderType.GOOGLE, revoked=True
    )

    assert sample_user.id in GoogleLinkReportController.run(db_session).user_ids


def test_superadmin_is_reported_separately(db_session, superuser):
    _plant_session(db_session, superuser.id, external=True)

    report = GoogleLinkReportController.run(db_session)

    assert superuser.id in report.user_ids
    assert superuser.id in report.superadmin_ids


def test_plain_password_session_is_not_listed(db_session, sample_user):
    _plant_session(db_session, sample_user.id)

    assert sample_user.id not in GoogleLinkReportController.run(db_session).user_ids


def test_google_account_is_not_listed(db_session, google_user):
    _plant_session(
        db_session, google_user.id, provider=AuthProviderType.GOOGLE, external=True
    )

    assert google_user.id not in GoogleLinkReportController.run(db_session).user_ids


def test_report_counts_and_clean_flag():
    uid = uuid.uuid4()
    assert GoogleLinkReport(user_ids=(), superadmin_ids=()).clean
    report = GoogleLinkReport(user_ids=(uid,), superadmin_ids=())
    assert report.count == 1
    assert not report.clean
