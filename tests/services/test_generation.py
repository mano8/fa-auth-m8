"""Unit tests for the authorization-generation primitives and controller.

Covers the framework-neutral helpers (fail-closed increment, staleness
predicate, retention horizon) and the DB-facing :class:`GenerationController`
(generation bump, idempotent max tombstone upsert, tombstone lookup, the
DB-authoritative stale-generation check used by the introspection path, and the
tombstone cleanup guarded by *both* the retention horizon and the "no undelivered
outbox effect references this subject" rule) — 3.5.1 ``REV-GEN-01``.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.db_models.outbox import (
    EFFECT_PUBLISH,
    STATUS_COMPLETED,
    STATUS_DEAD,
    STATUS_LEASED,
    STATUS_PENDING,
    USER_WIDE_TARGET,
    RevocationOutbox,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import User
from auth_user_service.services.generation import (
    GENERATION_MAX,
    GENERATION_START,
    GenerationController,
    GenerationOverflowError,
    JtiStatusDecision,
    is_session_generation_stale,
    next_generation,
    tombstone_retention_seconds,
)


def _add_outbox_row(db_session, user_id: uuid.UUID, *, status: str) -> RevocationOutbox:
    """Commit one user-wide publish effect for *user_id* in the given state."""
    row = RevocationOutbox(
        user_id=user_id,
        auth_generation=2,
        effect_type=EFFECT_PUBLISH,
        target_digest=USER_WIDE_TARGET,
        payload={"user_id": str(user_id), "jti": None},
        status=status,
    )
    db_session.add(row)
    db_session.commit()
    return row


def _stamp_session(
    db_session, user, *, jti: str, generation: int | None
) -> ClientSession:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cs = ClientSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        provider=user.provider,
        jwt_jti=jti,
        refresh_token_hash="s" * 64,
        jwt_expires_at=now + timedelta(hours=1),
        refresh_expires_at=now + timedelta(days=7),
        revoked=False,
        auth_generation=generation,
    )
    db_session.add(cs)
    db_session.commit()
    db_session.refresh(cs)
    return cs


class TestNextGeneration:
    def test_increments_by_one(self):
        assert next_generation(GENERATION_START) == GENERATION_START + 1

    def test_fails_closed_at_ceiling(self):
        with pytest.raises(GenerationOverflowError):
            next_generation(GENERATION_MAX)

    def test_fails_closed_above_ceiling(self):
        # Defensive: a value already at/over the ceiling never wraps.
        with pytest.raises(GenerationOverflowError):
            next_generation(GENERATION_MAX + 1)


class TestIsSessionGenerationStale:
    def test_none_is_stale(self):
        assert is_session_generation_stale(None, 5) is True

    def test_equal_is_current(self):
        assert is_session_generation_stale(5, 5) is False

    def test_older_is_stale(self):
        assert is_session_generation_stale(4, 5) is True


class TestTombstoneRetentionSeconds:
    def test_uses_longest_of_every_horizon_component(self):
        from auth_user_service.services import generation as gen

        expected = max(
            gen.settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            gen.settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
            gen.settings.OUTBOX_COMPLETED_RETENTION_SECONDS,
            gen.settings.TOMBSTONE_CONSUMER_HORIZON_SECONDS,
        )
        assert tombstone_retention_seconds() == expected

    @pytest.mark.parametrize(
        "attribute, value",
        [
            ("ACCESS_TOKEN_EXPIRE_MINUTES", 10**6 // 60),
            ("REFRESH_TOKEN_EXPIRE_MINUTES", 10**6 // 60),
            ("OUTBOX_COMPLETED_RETENTION_SECONDS", 10**6),
            ("TOMBSTONE_CONSUMER_HORIZON_SECONDS", 10**6),
        ],
    )
    def test_each_component_can_dominate(self, monkeypatch, attribute, value):
        # Every component of the 3.5.1 horizon is load-bearing: raising any one
        # of them alone raises the retention. Guards against a component being
        # dropped from the max() without a test noticing.
        from auth_user_service.services import generation as gen

        monkeypatch.setattr(gen.settings, attribute, value)
        assert tombstone_retention_seconds() >= 10**6 - 60


class TestBumpUserGeneration:
    def test_increments_in_place(self, db_session, sample_user):
        start = sample_user.auth_generation
        new = GenerationController.bump_user_generation(sample_user)
        assert new == start + 1
        assert sample_user.auth_generation == start + 1

    def test_fails_closed_on_overflow(self, sample_user):
        sample_user.auth_generation = GENERATION_MAX
        with pytest.raises(GenerationOverflowError):
            GenerationController.bump_user_generation(sample_user)


class TestWriteDeletionTombstone:
    def test_inserts_terminal_generation(self, db_session, sample_user):
        tombstone = GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        assert tombstone.user_id == sample_user.id
        assert tombstone.terminal_generation == sample_user.auth_generation + 1

    def test_upsert_keeps_highest_generation(self, db_session, sample_user):
        GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        # A replayed delete at a *higher* current generation raises the terminal.
        sample_user.auth_generation += 5
        again = GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        assert again.terminal_generation == sample_user.auth_generation + 1

    def test_upsert_never_lowers_generation(self, db_session, sample_user):
        sample_user.auth_generation = 10
        first = GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        high = first.terminal_generation
        # A stale replay carrying a *lower* generation must not lower the terminal.
        sample_user.auth_generation = 2
        again = GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        assert again.terminal_generation == high


class TestSubjectIsTombstoned:
    def test_true_when_present(self, db_session, sample_user):
        GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        assert (
            GenerationController.subject_is_tombstoned(db_session, sample_user.id)
            is True
        )

    def test_false_when_absent(self, db_session):
        assert (
            GenerationController.subject_is_tombstoned(db_session, uuid.uuid4())
            is False
        )


class TestSessionGenerationIsStale:
    def test_current_session_is_not_stale(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        assert (
            GenerationController.session_generation_is_stale(
                db_session, cs.jwt_jti, sample_user.id
            )
            is False
        )

    def test_tombstoned_subject_is_stale(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        assert (
            GenerationController.session_generation_is_stale(
                db_session, cs.jwt_jti, sample_user.id
            )
            is True
        )

    def test_missing_session_is_stale(self, db_session, sample_user):
        assert (
            GenerationController.session_generation_is_stale(
                db_session, "no-such-jti", sample_user.id
            )
            is True
        )

    def test_owner_mismatch_is_stale(self, db_session, sample_user, superuser):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        # The session belongs to sample_user; asserting a different subject fails.
        assert (
            GenerationController.session_generation_is_stale(
                db_session, cs.jwt_jti, superuser.id
            )
            is True
        )

    def test_inactive_owner_is_stale(self, db_session, inactive_user):
        cs = _stamp_session(
            db_session,
            inactive_user,
            jti=str(uuid.uuid4()),
            generation=inactive_user.auth_generation,
        )
        assert (
            GenerationController.session_generation_is_stale(
                db_session, cs.jwt_jti, inactive_user.id
            )
            is True
        )

    def test_stale_generation_is_rejected(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        # Owner moves forward a generation; the stamped session is now stale.
        sample_user.auth_generation += 1
        db_session.add(sample_user)
        db_session.commit()
        assert (
            GenerationController.session_generation_is_stale(
                db_session, cs.jwt_jti, sample_user.id
            )
            is True
        )

    def test_legacy_null_generation_is_rejected(self, db_session, sample_user):
        cs = _stamp_session(
            db_session, sample_user, jti=str(uuid.uuid4()), generation=None
        )
        assert (
            GenerationController.session_generation_is_stale(
                db_session, cs.jwt_jti, sample_user.id
            )
            is True
        )


class TestCleanupExpiredTombstones:
    def _write_tombstone(self, db_session, *, updated_at: datetime) -> uuid.UUID:
        user_id = uuid.uuid4()
        tombstone = AuthTombstone(
            user_id=user_id,
            terminal_generation=2,
            updated_at=updated_at,
        )
        db_session.add(tombstone)
        db_session.commit()
        return user_id

    def test_deletes_rows_past_horizon(self, db_session):
        now = datetime.now(timezone.utc)
        horizon = tombstone_retention_seconds()
        old_id = self._write_tombstone(
            db_session,
            updated_at=(now - timedelta(seconds=horizon + 60)).replace(tzinfo=None),
        )
        deleted = GenerationController.cleanup_expired_tombstones(db_session, now=now)
        assert deleted == 1
        assert db_session.get(AuthTombstone, old_id) is None

    def test_retains_rows_within_horizon(self, db_session):
        now = datetime.now(timezone.utc)
        fresh_id = self._write_tombstone(
            db_session, updated_at=now.replace(tzinfo=None)
        )
        deleted = GenerationController.cleanup_expired_tombstones(db_session, now=now)
        assert deleted == 0
        assert db_session.get(AuthTombstone, fresh_id) is not None

    def test_defaults_now_to_current_time(self, db_session):
        # No rows → nothing deleted, and the default ``now`` branch is exercised.
        assert GenerationController.cleanup_expired_tombstones(db_session) == 0

    @pytest.mark.parametrize("status", [STATUS_PENDING, STATUS_LEASED, STATUS_DEAD])
    def test_retains_row_referenced_by_undelivered_effect(self, db_session, status):
        # 3.5.1: cleanup runs only when no undelivered outbox effect still names
        # the subject — however far past the retention horizon the tombstone is.
        now = datetime.now(timezone.utc)
        horizon = tombstone_retention_seconds()
        stale_id = self._write_tombstone(
            db_session,
            updated_at=(now - timedelta(seconds=horizon * 10)).replace(tzinfo=None),
        )
        _add_outbox_row(db_session, stale_id, status=status)

        deleted = GenerationController.cleanup_expired_tombstones(db_session, now=now)

        assert deleted == 0
        assert db_session.get(AuthTombstone, stale_id) is not None

    def test_deletes_row_once_its_effects_are_completed(self, db_session):
        # A completed row is finished: its own idempotency window is already
        # folded into the retention horizon, so it must not block cleanup.
        now = datetime.now(timezone.utc)
        horizon = tombstone_retention_seconds()
        stale_id = self._write_tombstone(
            db_session,
            updated_at=(now - timedelta(seconds=horizon + 60)).replace(tzinfo=None),
        )
        _add_outbox_row(db_session, stale_id, status=STATUS_COMPLETED)

        deleted = GenerationController.cleanup_expired_tombstones(db_session, now=now)

        assert deleted == 1
        assert db_session.get(AuthTombstone, stale_id) is None

    def test_guard_is_scoped_to_the_referenced_subject(self, db_session):
        # One subject's dead letter never pins another subject's tombstone.
        now = datetime.now(timezone.utc)
        horizon = tombstone_retention_seconds()
        updated_at = (now - timedelta(seconds=horizon + 60)).replace(tzinfo=None)
        pinned_id = self._write_tombstone(db_session, updated_at=updated_at)
        free_id = self._write_tombstone(db_session, updated_at=updated_at)
        _add_outbox_row(db_session, pinned_id, status=STATUS_DEAD)

        deleted = GenerationController.cleanup_expired_tombstones(db_session, now=now)

        assert deleted == 1
        assert db_session.get(AuthTombstone, pinned_id) is not None
        assert db_session.get(AuthTombstone, free_id) is None


class TestSubjectsWithUndeliveredEffects:
    def test_completed_effect_does_not_reference_its_subject(self, db_session):
        completed_id = uuid.uuid4()
        _add_outbox_row(db_session, completed_id, status=STATUS_COMPLETED)
        referenced = GenerationController.subjects_with_undelivered_effects(db_session)
        assert completed_id not in referenced

    def test_collects_every_undelivered_status(self, db_session):
        expected = set()
        for status in (STATUS_PENDING, STATUS_LEASED, STATUS_DEAD):
            user_id = uuid.uuid4()
            _add_outbox_row(db_session, user_id, status=status)
            expected.add(user_id)
        referenced = GenerationController.subjects_with_undelivered_effects(db_session)
        assert expected <= referenced


class _StubExec:
    """Minimal ``session.exec(...)`` result exposing ``.first()``."""

    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _StubSession:
    """In-memory ``Session`` stand-in for decision branches a real DB can't reach.

    The ``ck_user_superuser_role_consistency`` CHECK constraint forbids persisting
    a claim-inconsistent owner, and the session→user foreign key forbids a session
    whose owner row is absent, so those two ordered branches (3.5.2) are exercised
    against hand-built ORM objects instead.
    """

    def __init__(self, *, session_row, owner):
        self._session_row = session_row
        self._owner = owner

    def get(self, model, _key):
        if model is User:
            return self._owner
        return None  # no tombstone

    def exec(self, *_args, **_kwargs):
        return _StubExec(self._session_row)


class TestDecideJtiStatus:
    """The DB-authoritative subject-bound v2 decision (3.5.2, ``JTI-DECISION-01``)."""

    def test_active_current_session_canonical_owner(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        decision = GenerationController.decide_jti_status(
            db_session, cs.jwt_jti, sample_user.id
        )
        assert decision == JtiStatusDecision(
            active=True,
            user_id=sample_user.id,
            auth_generation=sample_user.auth_generation,
        )

    def test_tombstoned_subject_is_inactive(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        GenerationController.write_deletion_tombstone(
            session=db_session, user=sample_user
        )
        db_session.commit()
        decision = GenerationController.decide_jti_status(
            db_session, cs.jwt_jti, sample_user.id
        )
        assert decision.active is False

    def test_missing_session_is_inactive(self, db_session, sample_user):
        decision = GenerationController.decide_jti_status(
            db_session, "no-such-jti", sample_user.id
        )
        assert decision.active is False

    def test_revoked_session_is_inactive(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        cs.revoked = True
        db_session.add(cs)
        db_session.commit()
        decision = GenerationController.decide_jti_status(
            db_session, cs.jwt_jti, sample_user.id
        )
        assert decision.active is False

    def test_owner_mismatch_is_inactive(self, db_session, sample_user, superuser):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        # Session belongs to sample_user; asserting a different subject fails.
        decision = GenerationController.decide_jti_status(
            db_session, cs.jwt_jti, superuser.id
        )
        assert decision.active is False

    def test_inactive_owner_is_inactive(self, db_session, inactive_user):
        cs = _stamp_session(
            db_session,
            inactive_user,
            jti=str(uuid.uuid4()),
            generation=inactive_user.auth_generation,
        )
        decision = GenerationController.decide_jti_status(
            db_session, cs.jwt_jti, inactive_user.id
        )
        assert decision.active is False

    def test_stale_generation_is_inactive(self, db_session, sample_user):
        cs = _stamp_session(
            db_session,
            sample_user,
            jti=str(uuid.uuid4()),
            generation=sample_user.auth_generation,
        )
        sample_user.auth_generation += 1
        db_session.add(sample_user)
        db_session.commit()
        decision = GenerationController.decide_jti_status(
            db_session, cs.jwt_jti, sample_user.id
        )
        assert decision.active is False

    def test_missing_owner_is_inactive(self):
        # A session whose owner row is absent (FK-impossible in a real DB) is
        # revoked. Exercised with an in-memory session pointing at a missing owner.
        subject = uuid.uuid4()
        session_row = ClientSession(
            id=str(uuid.uuid4()),
            user_id=subject,
            provider=AuthProviderType.PASSWORD,
            jwt_jti="j" * 16,
            refresh_token_hash="s" * 64,
            revoked=False,
            auth_generation=1,
        )
        stub = _StubSession(session_row=session_row, owner=None)
        decision = GenerationController.decide_jti_status(stub, "j" * 16, subject)
        assert decision.active is False

    def test_claim_inconsistent_owner_is_inactive(self):
        # is_superuser=True with role=USER is a forbidden pair the DB CHECK would
        # reject, so build it in memory (table-model construction skips validation).
        subject = uuid.uuid4()
        owner = User(
            id=subject,
            email="inconsistent@example.com",
            provider=AuthProviderType.PASSWORD,
            is_active=True,
            is_superuser=True,
            role=RoleType.USER,
            auth_generation=1,
        )
        session_row = ClientSession(
            id=str(uuid.uuid4()),
            user_id=subject,
            provider=AuthProviderType.PASSWORD,
            jwt_jti="j" * 16,
            refresh_token_hash="s" * 64,
            revoked=False,
            auth_generation=1,
        )
        stub = _StubSession(session_row=session_row, owner=owner)
        decision = GenerationController.decide_jti_status(stub, "j" * 16, subject)
        assert decision.active is False
