"""Unit tests for the issuer-local API-key principal surface (3.11).

Covers the live owner-role limitation: ``get_current_api_key_principal`` resolves
the canonical ``ApiKeyPrincipal`` from the owner's current persisted claims via a
fresh query and rejects missing / inactive / claim-inconsistent owners with the
generic invalid-key response; ``require_api_key_role`` authorizes through the
shared SDK capability check so a key can never exceed its owner's current role
and never reaches administrative/superuser authority (capability ceiling).
"""

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from auth_sdk_m8.authorization import ApiKeyCapabilityCeilingError
from auth_sdk_m8.schemas.api_key import ApiKeyPrincipal
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

from auth_user_service.core.deps import (
    _resolve_api_key_principal,
    get_current_api_key_principal,
    get_current_api_key_reader,
    get_current_api_key_writer,
    require_api_key_role,
)


def _owner(role=RoleType.WRITER, is_superuser=False, is_active=True):
    """A minimal owner stand-in carrying only the fields the resolver reads."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        role=role,
        is_superuser=is_superuser,
        is_active=is_active,
        auth_generation=3,
    )


def _session_returning(owner):
    """A stub DB session whose owner query resolves to *owner*."""
    session = MagicMock()
    session.exec.return_value.first.return_value = owner
    return session


def _api_key(user_id=None, **attrs):
    return SimpleNamespace(user_id=user_id or uuid.uuid4(), **attrs)


class TestResolveApiKeyPrincipal:
    """The fresh live owner load and generic rejection (3.11)."""

    def test_active_consistent_owner_returns_principal(self):
        owner = _owner(role=RoleType.WRITER)
        principal = _resolve_api_key_principal(
            _session_returning(owner), _api_key(user_id=owner.id)
        )
        assert isinstance(principal, ApiKeyPrincipal)
        assert principal.user_id == str(owner.id)
        assert principal.role == RoleType.WRITER
        assert principal.auth_generation == 3
        # No access_mode column yet ⇒ most restrictive default.
        assert principal.access_mode == ApiKeyAccessMode.READ_ONLY
        assert principal.authentication_method == "api_key"

    def test_missing_owner_raises_generic_401(self):
        with pytest.raises(HTTPException) as exc:
            _resolve_api_key_principal(_session_returning(None), _api_key())
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid or expired API key"

    def test_inactive_owner_raises_generic_401(self):
        owner = _owner(is_active=False)
        with pytest.raises(HTTPException) as exc:
            _resolve_api_key_principal(
                _session_returning(owner), _api_key(user_id=owner.id)
            )
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid or expired API key"

    def test_inconsistent_owner_raises_generic_401(self):
        # role != SUPERADMIN with is_superuser=True is a broken persisted pair;
        # it must never resolve to a principal (same generic denial).
        owner = _owner(role=RoleType.USER, is_superuser=True)
        with pytest.raises(HTTPException) as exc:
            _resolve_api_key_principal(
                _session_returning(owner), _api_key(user_id=owner.id)
            )
        assert exc.value.status_code == 401

    def test_access_mode_read_from_key_when_present(self):
        # When the Expand migration adds the column, the surface reads it live.
        owner = _owner(role=RoleType.WRITER)
        principal = _resolve_api_key_principal(
            _session_returning(owner),
            _api_key(user_id=owner.id, access_mode=ApiKeyAccessMode.READ_WRITE),
        )
        assert principal.access_mode == ApiKeyAccessMode.READ_WRITE


class TestGetCurrentApiKeyPrincipalDb:
    """End-to-end resolution against a real DB owner + key row."""

    def _make_key(self, db_session, owner):
        from auth_user_service.core.security import SecurityHelper
        from auth_user_service.db_models.api_keys import ApiKey

        api_key = ApiKey(
            id=uuid.uuid4(),
            key_hash=SecurityHelper.hash_token("ak_" + uuid.uuid4().hex),
            user_id=owner.id,
            name="test-key",
        )
        db_session.add(api_key)
        db_session.commit()
        db_session.refresh(api_key)
        return api_key

    def test_returns_live_owner_principal(self, db_session, sample_user):
        api_key = self._make_key(db_session, sample_user)
        principal = get_current_api_key_principal(api_key=api_key, session=db_session)
        assert principal.user_id == str(sample_user.id)
        assert principal.role == sample_user.role
        assert principal.auth_generation == sample_user.auth_generation


class TestRequireApiKeyRole:
    """The shared-capability gate, its specializations, and the ceiling (3.11)."""

    def _principal(self, role, access_mode=ApiKeyAccessMode.READ_ONLY):
        return ApiKeyPrincipal(
            user_id=str(uuid.uuid4()),
            role=role,
            is_superuser=(role == RoleType.SUPERADMIN),
            access_mode=access_mode,
            auth_generation=1,
        )

    def test_reader_allows_owner_at_or_above_reader(self):
        dep = require_api_key_role(RoleType.READER)
        assert dep(self._principal(RoleType.WRITER)).role == RoleType.WRITER

    def test_reader_denies_owner_below_reader(self):
        dep = require_api_key_role(RoleType.READER)
        with pytest.raises(HTTPException) as exc:
            dep(self._principal(RoleType.USER))
        assert exc.value.status_code == 403

    def test_writer_denies_read_only_key_even_for_writer_owner(self):
        # Access-mode cap: a READ_ONLY key never writes, regardless of owner role.
        with pytest.raises(HTTPException) as exc:
            get_current_api_key_writer(self._principal(RoleType.WRITER))
        assert exc.value.status_code == 403

    def test_writer_allows_read_write_key_of_writer_owner(self):
        principal = self._principal(RoleType.WRITER, ApiKeyAccessMode.READ_WRITE)
        assert get_current_api_key_writer(principal).role == RoleType.WRITER

    def test_writer_denies_read_write_key_of_reader_owner(self):
        principal = self._principal(RoleType.READER, ApiKeyAccessMode.READ_WRITE)
        with pytest.raises(HTTPException) as exc:
            get_current_api_key_writer(principal)
        assert exc.value.status_code == 403

    def test_reader_specialization_is_a_reader_gate(self):
        assert get_current_api_key_reader(self._principal(RoleType.READER)) is not None

    @pytest.mark.parametrize("role", [RoleType.ADMIN, RoleType.SUPERADMIN])
    def test_ceiling_rejects_admin_and_superuser_requirements(self, role):
        # Requiring more than WRITER on an API-key path is a programming error,
        # rejected at wiring time — there is no admin/superuser API-key dep.
        with pytest.raises(ApiKeyCapabilityCeilingError):
            require_api_key_role(role)
