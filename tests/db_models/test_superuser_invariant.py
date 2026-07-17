"""Tests for the canonical ``is_superuser <=> role == SUPERADMIN`` invariant.

Covers three separated mechanisms (per the authorization contract §3.4):

* the model-layer invariant on ``User`` (fires through ``model_validate``),
* both non-NULL mismatch directions rejected by the named DB check constraint,
* the NULL case rejected by ``NOT NULL`` (a SQL CHECK passes on UNKNOWN), all
  exercised via raw SQL inserts that bypass the ORM.
"""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import text

from auth_user_service.db_models.users import (
    User,
    _SUPERUSER_ROLE_CHECK_NAME,
)
from auth_sdk_m8.authorization import InconsistentPrivilegeClaimsError
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

_TABLE = User.__tablename__


def _raw_insert(session, *, role, is_superuser):
    """Insert a user row via raw SQL, bypassing ORM validation.

    ``role``/``is_superuser`` may be raw SQL literals (including ``NULL``) so the
    engine constraints — not Python — decide acceptance.
    """
    stmt = text(
        f"INSERT INTO {_TABLE} "
        "(id, provider, email, is_active, email_verified, is_superuser, role) "
        f"VALUES (:id, 'PASSWORD', :email, 1, 0, {is_superuser}, {role})"
    )
    session.execute(
        stmt,
        {"id": uuid.uuid4().hex, "email": f"raw_{uuid.uuid4().hex[:8]}@example.com"},
    )
    session.commit()


class TestModelInvariant:
    """The model validator fires on ``User.model_validate`` (service path)."""

    def test_model_validate_accepts_canonical_superadmin(self):
        user = User.model_validate(
            {
                "id": uuid.uuid4(),
                "email": "ok-super@example.com",
                "provider": AuthProviderType.PASSWORD,
                "is_superuser": True,
                "role": RoleType.SUPERADMIN,
            }
        )
        assert user.is_superuser is True
        assert user.role == RoleType.SUPERADMIN

    def test_model_validate_accepts_canonical_non_superuser(self):
        user = User.model_validate(
            {
                "id": uuid.uuid4(),
                "email": "ok-user@example.com",
                "provider": AuthProviderType.PASSWORD,
                "is_superuser": False,
                "role": RoleType.USER,
            }
        )
        assert user.is_superuser is False

    def test_model_validate_rejects_flag_without_superadmin(self):
        with pytest.raises((InconsistentPrivilegeClaimsError, ValueError)):
            User.model_validate(
                {
                    "id": uuid.uuid4(),
                    "email": "bad1@example.com",
                    "provider": AuthProviderType.PASSWORD,
                    "is_superuser": True,
                    "role": RoleType.USER,
                }
            )

    def test_model_validate_rejects_superadmin_without_flag(self):
        with pytest.raises((InconsistentPrivilegeClaimsError, ValueError)):
            User.model_validate(
                {
                    "id": uuid.uuid4(),
                    "email": "bad2@example.com",
                    "provider": AuthProviderType.PASSWORD,
                    "is_superuser": False,
                    "role": RoleType.SUPERADMIN,
                }
            )


class TestDbCheckConstraint:
    """The DB constraint is authoritative for direct SQL and race paths."""

    def test_constraint_declared_on_table(self):
        names = {c.name for c in User.__table__.constraints if c.name is not None}
        assert _SUPERUSER_ROLE_CHECK_NAME in names

    def test_consistent_superadmin_row_allowed(self, db_session):
        _raw_insert(db_session, role="'SUPERADMIN'", is_superuser=1)

    def test_consistent_non_superuser_row_allowed(self, db_session):
        _raw_insert(db_session, role="'USER'", is_superuser=0)

    def test_flag_without_superadmin_rejected(self, db_session):
        with pytest.raises(IntegrityError):
            _raw_insert(db_session, role="'USER'", is_superuser=1)
        db_session.rollback()

    def test_superadmin_without_flag_rejected(self, db_session):
        with pytest.raises(IntegrityError):
            _raw_insert(db_session, role="'SUPERADMIN'", is_superuser=0)
        db_session.rollback()

    def test_null_flag_rejected_by_not_null(self, db_session):
        # A SQL CHECK passes on UNKNOWN, so the NULL case is caught by NOT NULL.
        with pytest.raises(IntegrityError):
            _raw_insert(db_session, role="'SUPERADMIN'", is_superuser="NULL")
        db_session.rollback()

    def test_null_role_rejected_by_not_null(self, db_session):
        with pytest.raises(IntegrityError):
            _raw_insert(db_session, role="NULL", is_superuser=0)
        db_session.rollback()
