"""Unit tests for auth_user_service.events.hub.

The SSE generator is driven with ``asyncio.run`` rather than a pytest async
plugin so the suite stays dependency-free. The thread-safe fan-out is exercised
directly via ``_fanout`` (the loop-thread half of ``publish``) except where the
``publish`` scheduling path itself is under test.
"""

import asyncio

import pytest

import auth_user_service.events.hub as hubmod
from auth_user_service.events import metrics as metmod
from auth_user_service.events.hub import (
    EVENT_SESSION_REVOKED,
    EVENT_USER_DELETED,
    _CLOSE,
    _GAP_FRAME,
    _HEARTBEAT_FRAME,
    EventHub,
    _BufferedEvent,
    _format,
    _parse_event_id,
    _Subscriber,
    emit,
    get_hub,
    init_hub,
)


def _make_hub(
    buffer_size: int = 10,
    heartbeat_seconds: float = 5.0,
    max_queue: int = 10,
    signing_key: str | None = "k",
) -> EventHub:
    return EventHub(
        buffer_size=buffer_size,
        heartbeat_seconds=heartbeat_seconds,
        max_queue=max_queue,
        signing_key=signing_key,
    )


class TestEventNameConstants:
    def test_wire_names_are_hyphenated(self):
        assert EVENT_SESSION_REVOKED == "session-revoked"
        assert EVENT_USER_DELETED == "user-deleted"


class TestParseEventId:
    def test_valid(self):
        assert _parse_event_id("100-5") == ("100", 5)

    def test_no_separator(self):
        assert _parse_event_id("abc") is None

    def test_empty_epoch(self):
        assert _parse_event_id("-5") is None

    def test_non_integer_seq(self):
        assert _parse_event_id("100-x") is None


class TestFormat:
    def test_frame_layout(self):
        ev = _BufferedEvent(
            seq=2, event_id="e-2", event_type="session-revoked", data='{"x":1}'
        )
        assert _format(ev) == 'id: e-2\nevent: session-revoked\ndata: {"x":1}\n\n'


class TestFanout:
    def test_buffers_and_assigns_monotonic_ids(self):
        hub = _make_hub()
        hub._fanout("session-revoked", "d1")
        hub._fanout("user-deleted", "d2")
        assert [e.seq for e in hub._buffer] == [1, 2]
        assert hub._buffer[0].event_id == f"{hub._epoch}-1"
        assert hub._buffer[1].event_type == "user-deleted"

    def test_ring_buffer_evicts_oldest(self):
        hub = _make_hub(buffer_size=2)
        for i in range(3):
            hub._fanout("e", f"d{i}")
        assert [e.seq for e in hub._buffer] == [2, 3]

    def test_skips_overflowed_subscriber(self):
        hub = _make_hub(max_queue=1)
        sub = _Subscriber(1)
        sub.overflow = True
        hub._subscribers.add(sub)
        hub._fanout("e", "d1")
        # Overflowed subscriber is skipped — nothing enqueued.
        assert sub.queue.qsize() == 0


class TestPublish:
    def test_noop_without_bound_loop(self):
        hub = _make_hub()
        hub.publish("session-revoked", {"a": 1})
        assert len(hub._buffer) == 0

    def test_schedules_fanout_on_loop(self):
        async def scenario():
            hub = _make_hub()
            hub.bind_loop(asyncio.get_running_loop())
            hub.publish(
                "session-revoked",
                {"event_type": "session.revoked", "user_id": "u1"},
            )
            await asyncio.sleep(0)
            assert len(hub._buffer) == 1
            assert "u1" in hub._buffer[0].data

        asyncio.run(scenario())


class TestResume:
    def test_none_is_fresh_resumable(self):
        assert _make_hub()._resume(None) == ([], True)

    def test_malformed_id_is_unresumable(self):
        assert _make_hub()._resume("garbage") == ([], False)

    def test_different_epoch_is_unresumable(self):
        hub = _make_hub()
        assert hub._resume("1-1") == ([], False)

    def test_empty_buffer_at_head_is_resumable(self):
        hub = _make_hub()
        assert hub._resume(f"{hub._epoch}-0") == ([], True)

    def test_empty_buffer_behind_is_unresumable(self):
        hub = _make_hub()
        hub._seq = 5
        assert hub._resume(f"{hub._epoch}-1") == ([], False)

    def test_replays_buffered_gap(self):
        hub = _make_hub()
        hub._fanout("e", "d1")
        hub._fanout("e", "d2")
        frames, resumable = hub._resume(f"{hub._epoch}-1")
        assert resumable is True
        assert [f.seq for f in frames] == [2]

    def test_evicted_gap_is_unresumable(self):
        hub = _make_hub(buffer_size=1)
        for i in range(3):
            hub._fanout("e", f"d{i}")
        frames, resumable = hub._resume(f"{hub._epoch}-1")
        assert resumable is False
        assert frames == []


class TestStream:
    def test_heartbeat_on_idle(self):
        async def scenario():
            hub = _make_hub(heartbeat_seconds=0.01)
            agen = hub.stream(None)
            frame = await agen.__anext__()
            assert frame == _HEARTBEAT_FRAME
            await agen.aclose()

        asyncio.run(scenario())

    def test_gap_signal_on_unresumable(self):
        async def scenario():
            hub = _make_hub()
            agen = hub.stream("1-1")  # wrong epoch
            frame = await agen.__anext__()
            assert frame == _GAP_FRAME
            await agen.aclose()

        asyncio.run(scenario())

    def test_replays_then_streams(self):
        async def scenario():
            hub = _make_hub()
            hub._fanout("session-revoked", "d1")
            hub._fanout("user-deleted", "d2")
            agen = hub.stream(f"{hub._epoch}-1")
            frame = await agen.__anext__()
            assert frame == f"id: {hub._epoch}-2\nevent: user-deleted\ndata: d2\n\n"
            await agen.aclose()

        asyncio.run(scenario())

    def test_delivers_live_event(self):
        async def scenario():
            hub = _make_hub()
            agen = hub.stream(None)
            task = asyncio.ensure_future(agen.__anext__())
            await asyncio.sleep(0.02)
            assert hub.subscriber_count == 1
            hub._fanout("session-revoked", "d1")
            frame = await asyncio.wait_for(task, timeout=1)
            assert "event: session-revoked" in frame
            await agen.aclose()
            assert hub.subscriber_count == 0

        asyncio.run(scenario())

    def test_backpressure_disconnects_slow_consumer(self):
        async def scenario():
            hub = _make_hub(heartbeat_seconds=0.01, max_queue=1)
            agen = hub.stream(None)
            assert await agen.__anext__() == _HEARTBEAT_FRAME
            sub = next(iter(hub._subscribers))
            hub._fanout("e", "d1")  # fills the queue (maxsize 1)
            hub._fanout("e", "d2")  # QueueFull → overflow flagged
            assert sub.overflow is True
            hub._fanout("e", "d3")  # already overflowed → skipped branch
            with pytest.raises(StopAsyncIteration):
                await agen.__anext__()
            assert hub.subscriber_count == 0

        asyncio.run(scenario())

    def test_close_disconnects_consumer(self):
        async def scenario():
            hub = _make_hub()
            agen = hub.stream(None)
            task = asyncio.ensure_future(agen.__anext__())
            await asyncio.sleep(0.02)
            hub.close()
            with pytest.raises(StopAsyncIteration):
                await asyncio.wait_for(task, timeout=1)
            assert hub.subscriber_count == 0

        asyncio.run(scenario())

    def test_metrics_track_connection_lifecycle(self):
        metmod.setup(True, "/user")
        m = metmod.get()
        assert m is not None

        async def scenario():
            hub = _make_hub()
            agen = hub.stream(None)
            task = asyncio.ensure_future(agen.__anext__())
            await asyncio.sleep(0.02)
            assert m.connections._value.get() == 1.0
            hub._fanout("session-revoked", "d1")
            await asyncio.wait_for(task, timeout=1)
            await agen.aclose()
            assert m.connections._value.get() == 0.0

        asyncio.run(scenario())
        assert (
            m.published_total.labels(event_type="session-revoked")._value.get() == 1.0
        )
        assert m.disconnects_total.labels(reason="client")._value.get() >= 1.0


class TestClose:
    def test_handles_full_subscriber_queue(self):
        hub = _make_hub(max_queue=1)
        sub = _Subscriber(1)
        sub.queue.put_nowait(_CLOSE)  # saturate
        hub._subscribers.add(sub)
        hub.close()  # QueueFull on the sentinel put is swallowed
        assert hub.subscriber_count == 1


class TestBindLoop:
    def test_captures_running_loop(self):
        async def scenario():
            hub = _make_hub()
            loop = asyncio.get_running_loop()
            hub.bind_loop(loop)
            assert hub._loop is loop

        asyncio.run(scenario())


class TestEmit:
    def test_noop_when_hub_absent(self):
        hubmod._hub = None
        emit("session-revoked", {"a": 1})  # must not raise

    def test_publishes_to_hub(self, monkeypatch):
        class _Recording:
            def __init__(self):
                self.calls = []

            def publish(self, event_type, payload):
                self.calls.append((event_type, payload))

        rec = _Recording()
        monkeypatch.setattr(hubmod, "_hub", rec)
        emit("session-revoked", {"a": 1})
        assert rec.calls == [("session-revoked", {"a": 1})]

    def test_swallows_publish_errors(self, monkeypatch):
        class _Boom:
            def publish(self, event_type, payload):
                raise RuntimeError("boom")

        monkeypatch.setattr(hubmod, "_hub", _Boom())
        emit("session-revoked", {"a": 1})  # logged, never raised


class TestEpochCollisionFix:
    def test_epoch_uses_nanosecond_resolution(self, monkeypatch):
        """Epoch comes from time.time_ns() — a sub-second value — so two hubs
        started within the same wall-clock second produce distinct epochs and
        prevent a reconnecting consumer from being silently judged resumable
        after a process restart."""
        monkeypatch.setattr(hubmod.time, "time_ns", lambda: 1_700_000_000_999_999_999)
        hub = _make_hub()
        assert hub._epoch == "1700000000999999999"

    def test_two_instances_in_same_second_get_distinct_epochs(self, monkeypatch):
        """Two hubs started within the same second get different epochs."""
        ns_values = iter([1_700_000_000_000_000_001, 1_700_000_000_000_000_002])
        monkeypatch.setattr(hubmod.time, "time_ns", lambda: next(ns_values))
        h1 = _make_hub()
        h2 = _make_hub()
        assert h1._epoch != h2._epoch


class TestInitHub:
    def _set(self, monkeypatch, **kwargs):
        from auth_user_service.core.config import settings

        for key, value in kwargs.items():
            monkeypatch.setattr(settings, key, value)

    def test_disabled_yields_no_hub(self, monkeypatch):
        self._set(monkeypatch, EVENT_STREAM_ENABLED=False)
        assert init_hub() is None
        assert get_hub() is None

    def test_enabled_with_signing(self, monkeypatch):
        self._set(monkeypatch, EVENT_STREAM_ENABLED=True, EVENT_SIGNING_ENABLED=True)
        hub = init_hub()
        assert hub is not None
        assert hub._signing_key is not None
        assert get_hub() is hub

    def test_signing_disabled_uses_no_key(self, monkeypatch):
        self._set(monkeypatch, EVENT_STREAM_ENABLED=True, EVENT_SIGNING_ENABLED=False)
        hub = init_hub()
        assert hub is not None
        assert hub._signing_key is None

    def test_signing_enabled_but_key_missing(self, monkeypatch):
        self._set(
            monkeypatch,
            EVENT_STREAM_ENABLED=True,
            EVENT_SIGNING_ENABLED=True,
            EVENT_SIGNING_KEY=None,
        )
        hub = init_hub()
        assert hub is not None
        assert hub._signing_key is None
