"""Layer B: engine-enforced constraints, enums, and cascades (``TEST-DB-01``).

Everything here is a guarantee the SQLite unit surrogate is contractually
forbidden from certifying (4.6): native enum representation, the role/flag
equivalence ``CHECK``, ``BIGINT`` width, foreign-key cascades, and unique
constraints as the *engine* enforces them.

Constraint evidence is separated by mechanism (50): a ``CHECK`` written as
``is_superuser = (role = 'SUPERADMIN')`` evaluates to ``UNKNOWN`` — and
therefore passes — when either side is ``NULL``, so ``NOT NULL`` and the
``CHECK`` are proven by different tests that cannot pass for each other's
reason.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError
from sqlmodel import Session, select

from auth_sdk_m8.schemas.base import ApiKeyAccessMode, Period, RoleType

from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience, RateLimit
from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    STATUS_PENDING,
    RevocationOutbox,
)
from auth_user_service.db_models.security_policy import (
    SUPERUSER_SET_POLICY_KEY,
    SecurityPolicy,
)
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import User
from tests.integration.database._factories import (
    make_api_key,
    make_user,
    naive_utc,
    raw_insert_user,
    uuid_literal,
)
from tests.integration.database._schema import has_check_constraint

pytestmark = pytest.mark.database_integration

# PostgreSQL raises IntegrityError on a CHECK violation; MySQL/MariaDB raise
# OperationalError (errno 3819) through pymysql. Both derive from DBAPIError,
# so assertions target the shared base rather than one dialect's exception.
CONSTRAINT_VIOLATION = DBAPIError

_CHECK_NAME = "ck_user_superuser_role_consistency"


# ── role/flag equivalence CHECK (3.4) ─────────────────────────────────────────


class TestRoleFlagEquivalenceCheck:
    """The named equivalence CHECK, as the engine enforces it."""

    def test_check_constraint_exists(self, clean_database: sa.Engine) -> None:
        assert has_check_constraint(clean_database, User.__tablename__, _CHECK_NAME)

    @pytest.mark.parametrize(
        ("role", "is_superuser"),
        [("READER", True), ("SUPERADMIN", False)],
        ids=["flag-without-superadmin-role", "superadmin-role-without-flag"],
    )
    def test_rejects_both_mismatch_directions(
        self, clean_database: sa.Engine, role: str, is_superuser: bool
    ) -> None:
        """Neither mismatch direction can reach the table.

        Every ``NOT NULL`` column is supplied a valid value, so the only thing
        that can reject the row is the CHECK — the separation 50 requires.
        """
        with pytest.raises(CONSTRAINT_VIOLATION):
            raw_insert_user(clean_database, role=role, is_superuser=is_superuser)

    @pytest.mark.parametrize(
        ("role", "is_superuser"),
        [("READER", False), ("SUPERADMIN", True)],
        ids=["canonical-non-superuser", "canonical-superuser"],
    )
    def test_admits_both_canonical_pairs(
        self, clean_database: sa.Engine, role: str, is_superuser: bool
    ) -> None:
        raw_insert_user(clean_database, role=role, is_superuser=is_superuser)

    def test_null_flag_is_rejected_by_not_null_not_by_the_check(
        self, clean_database: sa.Engine
    ) -> None:
        """``NULL`` is refused by ``NOT NULL`` — the CHECK would pass it.

        ``is_superuser = (role = 'SUPERADMIN')`` is ``UNKNOWN`` when
        ``is_superuser`` is ``NULL``, and an ``UNKNOWN`` CHECK passes. This test
        exists so the ``NOT NULL`` guarantee is never mistaken for CHECK
        coverage.
        """
        with pytest.raises(CONSTRAINT_VIOLATION):
            with clean_database.begin() as conn:
                conn.execute(
                    sa.text(
                        "INSERT INTO auth_user (created_at, updated_at, provider, "
                        "email, is_active, email_verified, is_superuser, role, "
                        "auth_generation, id) VALUES (CURRENT_TIMESTAMP, "
                        "CURRENT_TIMESTAMP, 'PASSWORD', :email, true, true, NULL, "
                        "'READER', 1, :id)"
                    ),
                    {
                        "email": "null-flag@example.com",
                        "id": uuid_literal(clean_database, uuid.uuid4()),
                    },
                )


# ── native enum representation (3.4, 4.6) ─────────────────────────────────────


class TestRoleEnumRepresentation:
    """Each engine's own enum representation of the persisted label."""

    def test_role_column_is_a_native_enum_carrying_superadmin(
        self, clean_database: sa.Engine
    ) -> None:
        column = next(
            c
            for c in sa.inspect(clean_database).get_columns(User.__tablename__)
            if c["name"] == "role"
        )
        assert isinstance(column["type"], sa.Enum), (
            "role must persist as the engine's native enum type "
            "(PostgreSQL ENUM type / MySQL-family ENUM column), not free text"
        )
        assert "SUPERADMIN" in column["type"].enums

    def test_unknown_role_label_is_rejected_by_the_engine(
        self, clean_database: sa.Engine
    ) -> None:
        with pytest.raises(CONSTRAINT_VIOLATION):
            raw_insert_user(clean_database, role="OVERLORD", is_superuser=False)

    def test_canonical_label_round_trips_through_the_orm(
        self, it_session: Session
    ) -> None:
        user = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        it_session.expunge_all()
        reloaded = it_session.get(User, user.id)
        assert reloaded is not None
        assert reloaded.role is RoleType.SUPERADMIN
        assert reloaded.is_superuser is True


# ── generation columns (3.5.1) ────────────────────────────────────────────────


class TestGenerationColumns:
    """``BIGINT`` width and nullability of the authorization generation."""

    @pytest.mark.parametrize(
        "table", ["auth_user", "auth_client_session"], ids=["user", "session"]
    )
    def test_auth_generation_is_bigint(
        self, clean_database: sa.Engine, table: str
    ) -> None:
        column = next(
            c
            for c in sa.inspect(clean_database).get_columns(table)
            if c["name"] == "auth_generation"
        )
        assert isinstance(column["type"], sa.BigInteger), (
            f"{table}.auth_generation must be BIGINT so the monotonic counter "
            "cannot wrap (3.5.1)"
        )

    def test_generation_stores_a_value_beyond_32_bits(
        self, it_session: Session
    ) -> None:
        """A width claim is only real if the engine actually stores the value."""
        big = 2**40 + 7
        user = make_user(it_session, auth_generation=big)
        it_session.expunge_all()
        reloaded = it_session.get(User, user.id)
        assert reloaded is not None
        assert reloaded.auth_generation == big

    def test_session_generation_is_not_null_after_enforce(
        self, clean_database: sa.Engine
    ) -> None:
        owner = raw_insert_user(clean_database, role="READER", is_superuser=False)
        with pytest.raises(CONSTRAINT_VIOLATION):
            with clean_database.begin() as conn:
                conn.execute(
                    sa.text(
                        "INSERT INTO auth_client_session (created_at, updated_at, "
                        "provider, jwt_jti, refresh_token_hash, jwt_expires_at, "
                        "refresh_expires_at, revoked, id, user_id, auth_generation) "
                        "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                        "'null-generation', 'h', CURRENT_TIMESTAMP, "
                        "CURRENT_TIMESTAMP, false, 'sess-null-gen', :owner, NULL)"
                    ),
                    {"owner": uuid_literal(clean_database, owner)},
                )


# ── tombstone (3.5.1) ─────────────────────────────────────────────────────────


class TestTombstonePersistence:
    def test_tombstone_has_no_foreign_key_and_outlives_the_user(
        self, it_session: Session, clean_database: sa.Engine
    ) -> None:
        """The tombstone must survive the deletion it describes.

        A foreign key would cascade it away with the user row and destroy the
        only durable record that every token minted for that subject is revoked.
        """
        assert not sa.inspect(clean_database).get_foreign_keys(
            AuthTombstone.__tablename__
        ), "the tombstone must carry no FK to the user it outlives (3.5.1)"

        user = make_user(it_session)
        it_session.add(AuthTombstone(user_id=user.id, terminal_generation=2**33))
        it_session.commit()
        it_session.delete(it_session.get(User, user.id))
        it_session.commit()

        surviving = it_session.get(AuthTombstone, user.id)
        assert surviving is not None
        assert surviving.terminal_generation == 2**33


# ── API-key relations (§3.11, §3.12, APIKEY-LIFECYCLE-01) ─────────────────────


class TestApiKeyRelations:
    def test_access_mode_defaults_to_read_only_for_a_raw_insert(
        self, it_session: Session, clean_database: sa.Engine
    ) -> None:
        """The Expand server default is what backfills pre-existing keys.

        Proven with a raw insert that omits the column entirely: an ORM insert
        would supply the Python-side default and prove nothing about the
        migrated schema.
        """
        user = make_user(it_session)
        key_id = uuid.uuid4()
        with clean_database.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO auth_api_key (created_at, updated_at, name, "
                    "revoked, key_hash, user_id, id) VALUES (CURRENT_TIMESTAMP, "
                    "CURRENT_TIMESTAMP, 'legacy', false, :hash, :user_id, :id)"
                ),
                {
                    "hash": uuid.uuid4().hex * 2,
                    "user_id": uuid_literal(clean_database, user.id),
                    "id": uuid_literal(clean_database, key_id),
                },
            )
            mode = conn.execute(
                sa.text("SELECT access_mode FROM auth_api_key WHERE id = :id"),
                {"id": uuid_literal(clean_database, key_id)},
            ).scalar_one()
        assert mode == ApiKeyAccessMode.READ_ONLY.name

    def test_audience_rows_cascade_when_the_key_row_is_deleted(
        self, it_session: Session
    ) -> None:
        """``APIKEY-LIFECYCLE-01``: the dead-key purge deletes the parent row and
        relies on this cascade to clear the bindings — no audience-only delete
        path exists, so the cascade is the contract."""
        user = make_user(it_session)
        key_id = make_api_key(
            it_session, user, audiences=("consumer-a", "consumer-b")
        ).id
        assert (
            len(
                it_session.exec(
                    select(ApiKeyAudience).where(ApiKeyAudience.api_key_id == key_id)
                ).all()
            )
            == 2
        )

        it_session.execute(
            sa.text("DELETE FROM auth_api_key WHERE id = :id"),
            {"id": uuid_literal(it_session.get_bind(), key_id)},
        )
        it_session.commit()

        assert (
            it_session.exec(
                select(ApiKeyAudience).where(ApiKeyAudience.api_key_id == key_id)
            ).all()
            == []
        )

    def test_rate_limit_rows_cascade_when_the_key_row_is_deleted(
        self, it_session: Session
    ) -> None:
        user = make_user(it_session)
        key_id = make_api_key(it_session, user).id
        it_session.add(RateLimit(api_key_id=key_id, period=Period.MINUTE, limit=10))
        it_session.commit()

        it_session.execute(
            sa.text("DELETE FROM auth_api_key WHERE id = :id"),
            {"id": uuid_literal(it_session.get_bind(), key_id)},
        )
        it_session.commit()

        assert (
            it_session.exec(
                select(RateLimit).where(RateLimit.api_key_id == key_id)
            ).all()
            == []
        )

    def test_deleting_the_owner_cascades_keys_and_their_children(
        self, it_session: Session
    ) -> None:
        user = make_user(it_session)
        key_id = make_api_key(it_session, user, audiences=("consumer-a",)).id
        user_id = user.id
        it_session.execute(
            sa.text("DELETE FROM auth_user WHERE id = :id"),
            {"id": uuid_literal(it_session.get_bind(), user_id)},
        )
        it_session.commit()

        assert (
            it_session.exec(
                select(ApiKeyAudience).where(ApiKeyAudience.api_key_id == key_id)
            ).all()
            == []
        )
        assert it_session.exec(select(ApiKey).where(ApiKey.id == key_id)).all() == []

    def test_audience_binding_is_unique_per_key(self, it_session: Session) -> None:
        """The composite primary key is what makes a binding set a *set*."""
        user = make_user(it_session)
        key = make_api_key(it_session, user, audiences=("consumer-a",))
        it_session.add(
            ApiKeyAudience(
                api_key_id=key.id, audience_id="consumer-a", created_at=naive_utc()
            )
        )
        with pytest.raises(CONSTRAINT_VIOLATION):
            it_session.commit()
        it_session.rollback()

    def test_rate_limit_period_is_unique_per_key(self, it_session: Session) -> None:
        user = make_user(it_session)
        key = make_api_key(it_session, user)
        it_session.add(RateLimit(api_key_id=key.id, period=Period.MINUTE, limit=10))
        it_session.commit()
        it_session.add(RateLimit(api_key_id=key.id, period=Period.MINUTE, limit=99))
        with pytest.raises(CONSTRAINT_VIOLATION):
            it_session.commit()
        it_session.rollback()


# ── outbox (3.5.2) ────────────────────────────────────────────────────────────


class TestOutboxSchema:
    def _row(self, user_id: uuid.UUID, digest: str) -> RevocationOutbox:
        return RevocationOutbox(
            user_id=user_id,
            auth_generation=2,
            effect_type=EFFECT_BLACKLIST,
            target_digest=digest,
            payload={"jti": "j", "expires_at": naive_utc().isoformat()},
            status=STATUS_PENDING,
        )

    def test_effect_target_uniqueness_collapses_a_duplicate_enqueue(
        self, it_session: Session
    ) -> None:
        """Duplicate enqueue is harmless *because* the engine refuses the twin."""
        user = make_user(it_session)
        it_session.add(self._row(user.id, "digest-1"))
        it_session.commit()
        it_session.add(self._row(user.id, "digest-1"))
        with pytest.raises(CONSTRAINT_VIOLATION):
            it_session.commit()
        it_session.rollback()

    def test_distinct_targets_coexist(self, it_session: Session) -> None:
        user = make_user(it_session)
        it_session.add(self._row(user.id, "digest-1"))
        it_session.add(self._row(user.id, "digest-2"))
        it_session.commit()
        assert (
            len(
                it_session.exec(
                    select(RevocationOutbox).where(RevocationOutbox.user_id == user.id)
                ).all()
            )
            == 2
        )

    def test_claim_path_columns_are_indexed(self, clean_database: sa.Engine) -> None:
        """``user_id`` and ``status`` carry indexes — the drain scans on them."""
        indexed = {
            tuple(index["column_names"])
            for index in sa.inspect(clean_database).get_indexes(
                RevocationOutbox.__tablename__
            )
        }
        flattened = {column for columns in indexed for column in columns}
        assert {"user_id", "status"} <= flattened

    def test_outbox_rows_have_no_foreign_key_to_the_user(
        self, clean_database: sa.Engine
    ) -> None:
        """A pending effect must survive the hard delete that produced it."""
        assert not sa.inspect(clean_database).get_foreign_keys(
            RevocationOutbox.__tablename__
        )


# ── security policy singleton (3.5.3) ─────────────────────────────────────────


class TestSecurityPolicySeed:
    def test_singleton_row_is_seeded_by_expand(self, it_session: Session) -> None:
        rows = it_session.exec(select(SecurityPolicy)).all()
        assert [row.policy_key for row in rows] == [SUPERUSER_SET_POLICY_KEY]

    def test_policy_key_is_the_primary_key(self, clean_database: sa.Engine) -> None:
        pk = sa.inspect(clean_database).get_pk_constraint(SecurityPolicy.__tablename__)
        assert pk["constrained_columns"] == ["policy_key"]
