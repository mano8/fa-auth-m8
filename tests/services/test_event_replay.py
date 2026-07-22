"""Event replay / duplication / reordering convergence for the revocation outbox.

The durable outbox is the issuer half of the at-least-once revocation-propagation
contract (3.5.2). This suite proves the properties a consumer relies on to
converge under replay and reordering, from the *producer* side:

* a duplicate user-wide effect for the same ``(user_id, auth_generation)``
  collapses onto the one unique row (duplicate ``jti=None`` events are harmless);
* the durable ``event_id`` is deterministic, so a re-enqueue/replay carries the
  same dedup key;
* a newer generation's event carries a strictly higher watermark than an older
  one, so an older-generation event can never overwrite newer state;
* the per-JTI blacklist and the user-wide publish for one change converge (both
  effects delivered); and
* a duplicate drain (worker restart/replay) is idempotent — the effect is
  applied once and the revocation is preserved.

These complement ``test_outbox`` (which owns enqueue shape / claim-lease /
retry / dead-letter) with the explicit replay/reorder framing of §6.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import delete, select

import auth_user_service.events.hub as hubmod
from auth_user_service.db_models.outbox import (
    EFFECT_PUBLISH,
    STATUS_COMPLETED,
    USER_WIDE_TARGET,
    RevocationOutbox,
)
from auth_user_service.services.client_sessions import RevocationTarget
from auth_user_service.services.outbox import (
    EVENT_SCHEMA_V2,
    OutboxController,
    OutboxWorker,
    _event_id,
)


def _future(hours: int = 1) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=hours)


class _RecordingRedis:
    """Redis stand-in that records blacklist writes and revocations."""

    def __init__(self) -> None:
        self.setex_calls: list[tuple] = []
        self.delete_calls: list[str] = []

    def setex(self, key, ttl, value):
        self.setex_calls.append((key, ttl, value))

    def delete(self, key):
        self.delete_calls.append(key)


@pytest.fixture(autouse=True)
def _clean_outbox(db_session):
    """Isolate each test — the drain worker claims all pending rows globally."""
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


class TestDuplicateEnqueueIsDeduplicated:
    def test_duplicate_user_wide_effect_hits_unique_constraint(self, db_session):
        """Two user-wide publishes for the same (user, generation) collapse.

        The unique key ``(user_id, auth_generation, effect_type, target_digest)``
        makes a replayed enqueue of the same generation's user-wide event a
        no-op-or-conflict, never a second divergent event.
        """
        uid = uuid.uuid4()
        OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=5, targets=[]
        )
        db_session.commit()
        # Re-enqueue the identical user-wide effect for the same generation.
        OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=5, targets=[]
        )
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

        rows = db_session.exec(
            select(RevocationOutbox).where(
                RevocationOutbox.user_id == uid,
                RevocationOutbox.effect_type == EFFECT_PUBLISH,
            )
        ).all()
        assert len(rows) == 1

    def test_duplicate_blacklist_target_in_same_generation_collapses(self, db_session):
        """The same JTI captured twice for one generation is one blacklist row."""
        uid = uuid.uuid4()
        target = RevocationTarget(jti="dup-jti", expires_at=_future())
        OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=7, targets=[target, target]
        )
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()


class TestReorderingWatermark:
    def test_event_id_is_deterministic_across_replays(self, db_session):
        """A re-derived durable event_id is identical — the consumer dedup key."""
        uid = uuid.uuid4()
        rows = OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=9, targets=[]
        )
        db_session.commit()
        publish = next(r for r in rows if r.effect_type == EFFECT_PUBLISH)
        assert publish.payload["event_id"] == _event_id(
            str(uid), 9, EFFECT_PUBLISH, USER_WIDE_TARGET
        )

    def test_newer_generation_carries_strictly_higher_watermark(self, db_session):
        """An older-generation event can never overwrite newer state.

        Each generation's user-wide event carries its own ``auth_generation``
        watermark and a distinct durable ``event_id``; the newer generation's
        watermark is strictly greater, which is exactly the ``<``/``==``/``>``
        signal the consumer applies to reject a replayed older event.
        """
        uid = uuid.uuid4()
        older = OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=3, targets=[]
        )
        db_session.commit()
        newer = OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=4, targets=[]
        )
        db_session.commit()

        older_evt = next(r for r in older if r.effect_type == EFFECT_PUBLISH).payload
        newer_evt = next(r for r in newer if r.effect_type == EFFECT_PUBLISH).payload

        assert older_evt["version"] == EVENT_SCHEMA_V2
        assert newer_evt["version"] == EVENT_SCHEMA_V2
        assert newer_evt["auth_generation"] > older_evt["auth_generation"]
        assert newer_evt["event_id"] != older_evt["event_id"]


class TestConvergenceAndIdempotentDrain:
    def test_per_jti_and_user_wide_effects_both_deliver(
        self, db_session, recording_hub
    ):
        """Individual-JTI blacklist and the user-wide publish converge on drain."""
        uid = uuid.uuid4()
        target = RevocationTarget(jti="conv-jti", expires_at=_future())
        OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=2, targets=[target]
        )
        db_session.commit()

        redis = _RecordingRedis()
        stats = OutboxWorker().drain_once(
            db_session, redis, now=datetime.now(timezone.utc)
        )

        assert stats.claimed == 2
        assert stats.completed == 2
        # Blacklist effect delivered to Redis, publish fanned out to the hub.
        assert len(redis.setex_calls) == 1
        assert [e[0] for e in recording_hub.events]

    def test_duplicate_drain_is_idempotent(self, db_session, recording_hub):
        """A worker restart/replay re-draining completed rows changes nothing.

        Completed rows are retained (not reaped) so a second drain finds nothing
        due, the blacklist is written exactly once, and the revocation stands.
        """
        uid = uuid.uuid4()
        target = RevocationTarget(jti="idem-jti", expires_at=_future())
        OutboxController.enqueue_role_change_effects(
            db_session, user_id=uid, auth_generation=1, targets=[target]
        )
        db_session.commit()

        redis = _RecordingRedis()
        worker = OutboxWorker()
        now = datetime.now(timezone.utc)
        first = worker.drain_once(db_session, redis, now=now)
        second = worker.drain_once(db_session, redis, now=now)

        assert first.completed == 2
        assert second.claimed == 0
        # The blacklist write happened once across both drains (idempotent).
        assert len(redis.setex_calls) == 1

        remaining = db_session.exec(
            select(RevocationOutbox).where(RevocationOutbox.user_id == uid)
        ).all()
        assert all(r.status == STATUS_COMPLETED for r in remaining)
