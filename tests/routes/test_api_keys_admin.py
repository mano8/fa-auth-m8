"""Phase 7 limited superadmin API-key surface (§3.11/§3.12 review).

``routes/api_keys.py`` is a pre-existing live-tested surface (coverage-omitted),
so these unit tests focus on the new superadmin ``list + revoke`` behaviour and
the invariants that make it safe:

- listing another user's keys returns **metadata only** — never the raw key
  (never stored) or the stored ``key_hash`` (secret non-exposure invariant);
- the derived ``status`` reflects active / revoked / expired;
- revoking another user's key is a delete-equivalent that writes exactly one
  durable ``delete`` audit row atomically with the revocation;
- the revoke is idempotent-safe (409 on an already-revoked key) and 404 on a
  missing key, neither of which writes an audit row.

The routes are called directly with fixtures (the superuser dependency is
satisfied by passing the ``superuser`` principal), matching the existing
``test_sessions_audit`` style.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlmodel import select

from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAdminPublic
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.routes.api_keys import (
    admin_list_user_api_keys,
    admin_revoke_api_key,
)


def _make_key(
    db_session,
    *,
    user_id: uuid.UUID,
    name: str = "k",
    revoked: bool = False,
    expires_at=None,
    access_mode: ApiKeyAccessMode = ApiKeyAccessMode.READ_ONLY,
) -> ApiKey:
    key = ApiKey(
        name=name,
        key_hash=uuid.uuid4().hex + uuid.uuid4().hex,  # >= 64 chars, never exposed
        user_id=user_id,
        expires_at=expires_at,
        revoked=revoked,
        access_mode=access_mode,
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    return key


def _audit_for_pk(db_session, row_pk) -> list[PrivilegedActionAudit]:
    return list(
        db_session.exec(
            select(PrivilegedActionAudit).where(
                PrivilegedActionAudit.row_pk == str(row_pk)
            )
        ).all()
    )


def _audit_count(db_session) -> int:
    return len(db_session.exec(select(PrivilegedActionAudit)).all())


class TestAdminListUserApiKeys:
    def test_lists_only_the_target_users_keys_metadata_only(
        self, db_session, sample_user, superuser
    ) -> None:
        # Two keys for the target, one for someone else — the listing is scoped.
        _make_key(db_session, user_id=sample_user.id, name="a")
        _make_key(db_session, user_id=sample_user.id, name="b")
        _make_key(db_session, user_id=superuser.id, name="other")

        result = admin_list_user_api_keys(session=db_session, user_id=sample_user.id)

        assert result.count == 2
        assert len(result.data) == 2
        assert {row.name for row in result.data} == {"a", "b"}
        assert all(row.user_id == sample_user.id for row in result.data)
        assert all(isinstance(row, ApiKeyAdminPublic) for row in result.data)

    def test_response_never_exposes_key_material(
        self, db_session, sample_user, superuser
    ) -> None:
        _make_key(db_session, user_id=sample_user.id, name="secretkey")

        result = admin_list_user_api_keys(session=db_session, user_id=sample_user.id)

        row = result.data[0]
        dumped = row.model_dump()
        # Neither the stored hash nor a raw key field is present anywhere.
        assert "key_hash" not in dumped
        assert "plaintext" not in dumped
        assert "key" not in dumped
        # The exact metadata-only field set.
        assert set(dumped) == {
            "id",
            "name",
            "user_id",
            "revoked",
            "expires_at",
            "last_used_at",
            "created_at",
            "access_mode",
            "status",
        }

    def test_status_reflects_active_revoked_and_expired(
        self, db_session, sample_user
    ) -> None:
        now = datetime.now(timezone.utc)
        _make_key(db_session, user_id=sample_user.id, name="active")
        _make_key(db_session, user_id=sample_user.id, name="revoked", revoked=True)
        _make_key(
            db_session,
            user_id=sample_user.id,
            name="expired",
            expires_at=now - timedelta(days=1),
        )

        result = admin_list_user_api_keys(session=db_session, user_id=sample_user.id)
        by_name = {row.name: row.status for row in result.data}

        assert by_name["active"] == "active"
        assert by_name["revoked"] == "revoked"
        assert by_name["expired"] == "expired"

    def test_empty_when_target_has_no_keys(self, db_session, sample_user) -> None:
        result = admin_list_user_api_keys(session=db_session, user_id=sample_user.id)
        assert result.count == 0
        assert result.data == []

    def test_listing_writes_no_audit_row(self, db_session, sample_user) -> None:
        _make_key(db_session, user_id=sample_user.id)
        before = _audit_count(db_session)
        admin_list_user_api_keys(session=db_session, user_id=sample_user.id)
        assert _audit_count(db_session) == before


class TestAdminRevokeApiKey:
    def test_revoke_writes_one_delete_audit_row_and_revokes(
        self, db_session, sample_user, superuser
    ) -> None:
        key = _make_key(db_session, user_id=sample_user.id)
        key_id = key.id

        result = admin_revoke_api_key(
            session=db_session, current_user=superuser, key_id=key_id
        )
        assert result.message == "API key revoked successfully"

        # The authoritative row is revoked (delete-equivalent) and committed.
        db_session.expire_all()
        assert db_session.get(ApiKey, key_id).revoked is True

        rows = _audit_for_pk(db_session, key_id)
        assert len(rows) == 1
        row = rows[0]
        assert row.action == AuditAction.DELETE
        assert row.actor_user_id == superuser.id
        assert row.actor_role == RoleType.SUPERADMIN
        assert row.table_name == ApiKey.__tablename__
        assert row.row_pk == str(key_id)
        # The owner is captured before the mutation, not the acting superuser.
        assert row.target_owner_id == str(sample_user.id)

    def test_missing_key_is_404_and_writes_no_audit_row(
        self, db_session, superuser
    ) -> None:
        before = _audit_count(db_session)
        with pytest.raises(HTTPException) as exc:
            admin_revoke_api_key(
                session=db_session, current_user=superuser, key_id=uuid.uuid4()
            )
        assert exc.value.status_code == 404
        assert _audit_count(db_session) == before

    def test_already_revoked_key_is_409_and_writes_no_audit_row(
        self, db_session, sample_user, superuser
    ) -> None:
        key = _make_key(db_session, user_id=sample_user.id, revoked=True)
        before = _audit_count(db_session)
        with pytest.raises(HTTPException) as exc:
            admin_revoke_api_key(
                session=db_session, current_user=superuser, key_id=key.id
            )
        assert exc.value.status_code == 409
        assert _audit_count(db_session) == before
