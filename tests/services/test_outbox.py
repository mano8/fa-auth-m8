"""Unit tests for the transactional revocation outbox (services.outbox).

Covers enqueue shape (one blacklist row per captured JTI + one user-wide v2
publish row), the at-least-once drain worker (claim/lease/SKIP LOCKED, per-target
expiry-derived blacklist TTL, the durable v2 event payload), bounded-retry
backoff, the dead-letter path, abandoned-lease recovery, and completed-row
reaping (3.5.2 ``REV-OUTBOX-01``/``REV-EVENT-01``).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import delete, select

import auth_user_service.events.hub as hubmod
from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    STATUS_COMPLETED,
    STATUS_DEAD,
    STATUS_LEASED,
    STATUS_PENDING,
    USER_WIDE_TARGET,
    RevocationOutbox,
)
from auth_user_service.services.client_sessions import RevocationTarget
from auth_user_service.services.outbox import (
    EVENT_SCHEMA_V2,
    OutboxController,
    OutboxWorker,
    _digest_jti,
    _event_id,
)


def _future(hours: int = 1) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def _target(jti: str = "jti-1", *, expires_at: datetime = None) -> RevocationTarget:
    return RevocationTarget(jti=jti, expires_at=expires_at or _future())


class _RecordingRedis:
    """Minimal Redis stand-in recording setex/delete calls."""

    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.setex_calls: list[tuple] = []
        self.delete_calls: list[str] = []

    def setex(self, key, ttl, value):
        if self.fail:
            raise ConnectionError("redis down")
        self.setex_calls.append((key, ttl, value))

    def delete(self, key):
        self.delete_calls.append(key)


@pytest.fixture(autouse=True)
def _clean_outbox(db_session):
    """Start each test with an empty outbox.

    The in-memory engine is session-scoped and committed rows persist across
    tests, but the drain worker claims **all** pending rows globally, so leftover
    rows from a sibling test would skew claim/complete counts. Clear the table
    up front for deterministic, isolated assertions.
    """
    db_session.exec(delete(RevocationOutbox))
    db_session.commit()
    yield


@pytest.fixture
def recording_hub(monkeypatch):
    class _Hub:
        def __init__(self):
            self.events = []

        def publish(self, event_type, payload):
            self.events.append((event_type, payload))

    hub = _Hub()
    monkeypatch.setattr(hubmod, "_hub", hub)
    return hub


class TestHelpers:
    def test_digest_is_stable_and_hides_jti(self):
        d = _digest_jti("secret-jti")
        assert d == _digest_jti("secret-jti")
        assert "secret-jti" not in d
        assert len(d) == 64  # sha256 hex

    def test_event_id_is_deterministic_tuple(self):
        assert (
            _event_id("u", 3, EFFECT_PUBLISH, USER_WIDE_TARGET)
            == "u:3:publish:user-wide"
        )


class TestEnqueue:
    def test_enqueues_blacklist_and_publish_rows(self, db_session):
        uid = uuid.uuid4()
        rows = OutboxController.enqueue_role_change_effects(
            db_session,
            user_id=uid,
            auth_generation=5,
            targets=[_target("jti-a"), _target("jti-b")],
        )
        db_session.commit()

        assert len(rows) == 3
        by_type = sorted(r.effect_type for r in rows)
        assert by_type == [EFFECT_BLACKLIST, EFFECT_BLACKLIST, EFFECT_PUBLISH]

        publish = next(r for r in rows if r.effect_type == EFFECT_PUBLISH)
        assert publish.target_digest == USER_WIDE_TARGET
        assert publish.payload["version"] == EVENT_SCHEMA_V2
        assert publish.payload["auth_generation"] == 5
        assert publish.payload["jti"] is None
        assert publish.payload["event_id"] == _event_id(
            str(uid), 5, EFFECT_PUBLISH, USER_WIDE_TARGET
        )
        for r in rows:
            assert r.status == STATUS_PENDING
            assert r.auth_generation == 5

    def test_no_targets_still_enqueues_user_wide_publish(self, db_session):
        rows = OutboxController.enqueue_role_change_effects(
            db_session, user_id=uuid.uuid4(), auth_generation=1, targets=[]
        )
        db_session.commit()
        assert [r.effect_type for r in rows] == [EFFECT_PUBLISH]

    def test_blacklist_payload_carries_jti_and_expiry(self, db_session):
        exp = _future(2)
        rows = OutboxController.enqueue_role_change_effects(
            db_session,
            user_id=uuid.uuid4(),
            auth_generation=1,
            targets=[_target("jti-x", expires_at=exp)],
        )
        db_session.commit()
        blk = next(r for r in rows if r.effect_type == EFFECT_BLACKLIST)
        assert blk.payload["jti"] == "jti-x"
        assert datetime.fromisoformat(blk.payload["expires_at"]) == exp


def _enqueue(db_session, *, targets, generation=1, user_id=None):
    OutboxController.enqueue_role_change_effects(
        db_session,
        user_id=user_id or uuid.uuid4(),
        auth_generation=generation,
        targets=targets,
    )
    db_session.commit()


class TestDrainSuccess:
    def test_blacklist_and_publish_complete(self, db_session, recording_hub):
        _enqueue(db_session, targets=[_target("jti-1")])
        redis = _RecordingRedis()
        worker = OutboxWorker()

        stats = worker.drain_once(db_session, redis)

        assert stats.claimed == 2
        assert stats.completed == 2
        assert stats.retried == 0 and stats.dead == 0
        remaining = db_session.exec(select(RevocationOutbox)).all()
        assert all(r.status == STATUS_COMPLETED for r in remaining)
        assert all(r.completed_at is not None for r in remaining)

        # Blacklist applied with a TTL derived from the captured expiry.
        assert len(redis.setex_calls) == 1
        _, ttl, _ = redis.setex_calls[0]
        assert 0 < ttl <= 3600
        assert redis.delete_calls  # refresh store revoke

        # Durable v2 event fanned out.
        assert len(recording_hub.events) == 1
        event_type, payload = recording_hub.events[0]
        assert event_type == "session-revoked"
        assert payload["version"] == EVENT_SCHEMA_V2
        assert payload["jti"] is None
        assert payload["event_id"]

    def test_expired_target_needs_no_redis(self, db_session):
        # A target already past expiry blacklists nothing and completes even
        # with redis=None.
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        _enqueue(db_session, targets=[_target("jti-old", expires_at=past)])
        worker = OutboxWorker()

        stats = worker.drain_once(db_session, None)

        assert stats.completed == 2  # blacklist (no-op) + publish
        blk = db_session.exec(
            select(RevocationOutbox).where(
                RevocationOutbox.effect_type == EFFECT_BLACKLIST
            )
        ).first()
        assert blk.status == STATUS_COMPLETED


class TestDrainRetryAndDeadLetter:
    def test_blacklist_without_redis_retries(self, db_session):
        _enqueue(db_session, targets=[_target("jti-1")])
        worker = OutboxWorker(max_attempts=3)

        # redis=None with a live (future) TTL cannot deliver → retry.
        stats = worker.drain_once(db_session, None)
        assert stats.retried == 1  # the blacklist row
        assert stats.completed == 1  # publish still completes

        blk = db_session.exec(
            select(RevocationOutbox).where(
                RevocationOutbox.effect_type == EFFECT_BLACKLIST
            )
        ).first()
        assert blk.status == STATUS_PENDING
        assert blk.attempts == 1
        assert blk.next_attempt_at is not None
        assert blk.lease_until is None

    def test_exhausted_retries_dead_letter(self, db_session):
        # Long-lived target so the blacklist stays deliverable across the whole
        # retry window (a shorter expiry would no-op as "already expired").
        _enqueue(db_session, targets=[_target("jti-1", expires_at=_future(24))])
        worker = OutboxWorker(max_attempts=2)
        failing = _RecordingRedis(fail=True)

        # Attempt 1 → retry (schedules next_attempt_at in the future).
        first_now = datetime.now(timezone.utc)
        worker.drain_once(db_session, failing, now=first_now)
        blk = db_session.exec(
            select(RevocationOutbox).where(
                RevocationOutbox.effect_type == EFFECT_BLACKLIST
            )
        ).first()
        assert blk.status == STATUS_PENDING and blk.attempts == 1

        # Attempt 2 (after backoff window) → dead-letter.
        later = first_now + timedelta(hours=1)
        worker.drain_once(db_session, failing, now=later)
        db_session.refresh(blk)
        assert blk.status == STATUS_DEAD
        assert blk.attempts == 2

    def test_backoff_grows_and_caps(self):
        worker = OutboxWorker(backoff_base_seconds=2.0, backoff_cap_seconds=10.0)
        assert worker._backoff(1) == timedelta(seconds=2)
        assert worker._backoff(2) == timedelta(seconds=4)
        assert worker._backoff(3) == timedelta(seconds=8)
        assert worker._backoff(4) == timedelta(seconds=10)  # capped


class TestClaimSemantics:
    def test_not_due_rows_are_skipped(self, db_session):

        _enqueue(db_session, targets=[])  # single publish row
        row = db_session.exec(select(RevocationOutbox)).first()
        row.next_attempt_at = datetime.now(timezone.utc) + timedelta(hours=1)
        db_session.add(row)
        db_session.commit()

        worker = OutboxWorker()
        stats = worker.drain_once(db_session, None)
        assert stats.claimed == 0

    def test_abandoned_lease_is_reclaimed(self, db_session):

        _enqueue(db_session, targets=[])
        row = db_session.exec(select(RevocationOutbox)).first()
        # Simulate a crashed worker: leased with an already-expired lease.
        row.status = STATUS_LEASED
        row.lease_until = datetime.now(timezone.utc) - timedelta(minutes=5)
        db_session.add(row)
        db_session.commit()

        worker = OutboxWorker()
        stats = worker.drain_once(db_session, None)
        assert stats.claimed == 1
        assert stats.completed == 1

    def test_live_lease_is_not_reclaimed(self, db_session):

        _enqueue(db_session, targets=[])
        row = db_session.exec(select(RevocationOutbox)).first()
        row.status = STATUS_LEASED
        row.lease_until = datetime.now(timezone.utc) + timedelta(minutes=5)
        db_session.add(row)
        db_session.commit()

        worker = OutboxWorker()
        stats = worker.drain_once(db_session, None)
        assert stats.claimed == 0


class TestReapCompleted:
    def test_reaps_old_completed_only(self, db_session):

        _enqueue(db_session, targets=[])
        worker = OutboxWorker(completed_retention_seconds=3600)
        worker.drain_once(db_session, None)

        row = db_session.exec(select(RevocationOutbox)).first()
        assert row.status == STATUS_COMPLETED

        # Not yet past retention → nothing reaped.
        assert worker.reap_completed(db_session) == 0

        # Backdate completion beyond retention → reaped.
        row.completed_at = datetime.now(timezone.utc) - timedelta(hours=2)
        db_session.add(row)
        db_session.commit()
        assert worker.reap_completed(db_session) == 1
        assert db_session.exec(select(RevocationOutbox)).all() == []


class TestFromSettings:
    def test_from_settings_maps_fields(self):
        from auth_user_service.core.config import settings

        worker = OutboxWorker.from_settings(settings)
        assert worker.batch_size == settings.OUTBOX_BATCH_SIZE
        assert worker.max_attempts == settings.OUTBOX_MAX_ATTEMPTS
        assert worker.lease_seconds == settings.OUTBOX_LEASE_SECONDS
        assert worker.completed_retention_seconds == (
            settings.OUTBOX_COMPLETED_RETENTION_SECONDS
        )
