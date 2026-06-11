"""In-process event hub + SSE fan-out for the fa-auth event-stream bridge.

The hub is a single in-process asyncio fan-out with a bounded ring buffer. Auth
routes (which FastAPI runs in a worker thread for ``def`` handlers) publish via
the thread-safe :meth:`EventHub.publish`; each connected consumer drains its own
bounded queue through :meth:`EventHub.stream`, an SSE generator.

Wire format (matches ``auth_sdk_m8.events.AuthEventStreamClient``)::

    id: <boot-epoch>-<seq>
    event: session-revoked | user-deleted
    data: {"payload": {...}, "sig": "<hex>"}     # _signing.serialize output

    : ping                                        # heartbeat comment frame
    event: gap                                    # unresumable-gap signal
    data: {}

Resume: a reconnecting consumer sends ``Last-Event-ID``. Same boot epoch with
the id still in the buffer ⇒ the gap is replayed; a different epoch (fa-auth
restarted) or an evicted id ⇒ the server emits an ``event: gap`` frame and the
consumer must flush its local validation caches. Push is a best-effort
accelerator — the JTI blacklist stays authoritative — so any failure degrades
to "slower cache eviction", never to incorrect authorization.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import AsyncIterator, Optional

from auth_sdk_m8.redis_events._signing import serialize

from auth_user_service.events import metrics as _event_metrics

logger = logging.getLogger(__name__)

# SSE ``event:`` field values (hyphenated wire names — distinct from the dotted
# ``event_type`` inside the signed payload, e.g. ``session.revoked``).
EVENT_SESSION_REVOKED = "session-revoked"
EVENT_USER_DELETED = "user-deleted"

_HEARTBEAT_FRAME = ": ping\n\n"
_GAP_FRAME = "event: gap\ndata: {}\n\n"

# Sentinel pushed into a subscriber queue to wake it for graceful shutdown.
_CLOSE = object()


@dataclass(frozen=True)
class _BufferedEvent:
    """An event retained in the ring buffer for Last-Event-ID resume."""

    seq: int
    event_id: str
    event_type: str
    data: str


class _Subscriber:
    """Per-connection state: a bounded queue plus an overflow flag."""

    __slots__ = ("queue", "overflow")

    def __init__(self, max_queue: int) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue)
        self.overflow = False


def _parse_event_id(event_id: str) -> Optional[tuple[str, int]]:
    """Split ``"<epoch>-<seq>"`` into ``(epoch, seq)``; None if malformed."""
    epoch, sep, seq = event_id.rpartition("-")
    if not sep or not epoch:
        return None
    try:
        return epoch, int(seq)
    except ValueError:
        return None


def _format(event: _BufferedEvent) -> str:
    """Render a buffered event as a complete SSE frame."""
    return f"id: {event.event_id}\nevent: {event.event_type}\ndata: {event.data}\n\n"


class EventHub:
    """In-process fan-out hub for the SSE bridge.

    Args:
        buffer_size: Ring-buffer depth for Last-Event-ID resume.
        heartbeat_seconds: Idle interval between heartbeat comment frames.
        max_queue: Per-connection outbound queue depth before a slow consumer
            is disconnected (it reconnects and resumes/flushes).
        signing_key: HMAC key for ``_signing.serialize``; ``None`` disables
            signing (consumers must also run unsigned).
    """

    def __init__(
        self,
        *,
        buffer_size: int,
        heartbeat_seconds: float,
        max_queue: int,
        signing_key: Optional[str],
    ) -> None:
        self._buffer: deque[_BufferedEvent] = deque(maxlen=buffer_size)
        self._heartbeat = heartbeat_seconds
        self._max_queue = max_queue
        self._signing_key = signing_key
        self._subscribers: set[_Subscriber] = set()
        self._epoch = str(time.time_ns())
        self._seq = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── lifecycle ───────────────────────────────────────────────────────────

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Capture the running event loop so publishers can hop onto it."""
        self._loop = loop

    def close(self) -> None:
        """Signal every connected consumer to disconnect (graceful shutdown)."""
        for sub in self._subscribers:
            try:
                sub.queue.put_nowait(_CLOSE)
            except asyncio.QueueFull:
                # Already saturated; the consumer wakes on its next drain and
                # the server cancels the request on shutdown regardless.
                pass

    @property
    def subscriber_count(self) -> int:
        """Number of currently connected consumers (test/introspection aid)."""
        return len(self._subscribers)

    # ── publishing ──────────────────────────────────────────────────────────

    def publish(self, event_type: str, payload: dict) -> None:
        """Thread-safely fan an event out to all consumers.

        Safe to call from a sync route handler running in FastAPI's worker
        thread: the actual fan-out is scheduled onto the captured event loop.
        A no-op until :meth:`bind_loop` has run.
        """
        loop = self._loop
        if loop is None:
            return
        data = serialize(payload, self._signing_key)
        loop.call_soon_threadsafe(self._fanout, event_type, data)

    def _fanout(self, event_type: str, data: str) -> None:
        """Assign an id, buffer the frame, and enqueue it for every consumer.

        Runs on the event loop thread (scheduled by :meth:`publish`).
        """
        self._seq += 1
        event = _BufferedEvent(
            seq=self._seq,
            event_id=f"{self._epoch}-{self._seq}",
            event_type=event_type,
            data=data,
        )
        self._buffer.append(event)

        m = _event_metrics.get()
        if m is not None:
            m.published_total.labels(event_type=event_type).inc()

        for sub in self._subscribers:
            if sub.overflow:
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                # Slow consumer — mark it for disconnect; it reconnects and
                # resumes/flushes. Never block the emitting request.
                sub.overflow = True

    # ── subscribing ─────────────────────────────────────────────────────────

    def _resume(
        self, last_event_id: Optional[str]
    ) -> tuple[list[_BufferedEvent], bool]:
        """Resolve a Last-Event-ID into (frames_to_replay, resumable)."""
        if last_event_id is None:
            return [], True
        parsed = _parse_event_id(last_event_id)
        if parsed is None:
            return [], False
        epoch, last_seq = parsed
        if epoch != self._epoch:
            return [], False
        if not self._buffer:
            # Same epoch, nothing retained: only resumable if the client is
            # already at the head (no events to miss).
            return [], last_seq >= self._seq
        if last_seq + 1 < self._buffer[0].seq:
            # The gap predates the buffer — cannot replay it.
            return [], False
        return [ev for ev in self._buffer if ev.seq > last_seq], True

    async def stream(self, last_event_id: Optional[str]) -> AsyncIterator[str]:
        """Yield SSE frames for one consumer until it disconnects.

        Replays any resumable gap (or emits an ``event: gap`` signal when the
        gap is unresumable), then streams live events with periodic heartbeats.
        """
        replay, resumable = self._resume(last_event_id)
        sub = _Subscriber(self._max_queue)
        self._subscribers.add(sub)
        reason = "client"
        m = _event_metrics.get()
        if m is not None:
            m.connections.inc()
        try:
            if not resumable:
                yield _GAP_FRAME
            for event in replay:
                yield _format(event)

            while True:
                if sub.overflow:
                    reason = "backpressure"
                    return
                try:
                    item = await asyncio.wait_for(
                        sub.queue.get(), timeout=self._heartbeat
                    )
                except asyncio.TimeoutError:
                    yield _HEARTBEAT_FRAME
                    continue
                if item is _CLOSE:
                    reason = "shutdown"
                    return
                yield _format(item)
        finally:
            self._subscribers.discard(sub)
            if m is not None:
                m.connections.dec()
                m.disconnects_total.labels(reason=reason).inc()


# ── module-level singleton ────────────────────────────────────────────────────

_hub: Optional[EventHub] = None


def init_hub() -> Optional[EventHub]:
    """Build the process-wide hub from settings, or None when disabled.

    Called once at startup. Reuses ``EVENT_SIGNING_KEY`` for payload signing
    (no separate key); signing is skipped only when event signing is disabled.
    """
    from auth_user_service.core.config import settings

    global _hub
    if not settings.EVENT_STREAM_ENABLED:
        _hub = None
        return None
    if settings.EVENT_SIGNING_ENABLED and settings.EVENT_SIGNING_KEY is not None:
        signing_key: Optional[str] = settings.EVENT_SIGNING_KEY.get_secret_value()
    else:
        signing_key = None
    _hub = EventHub(
        buffer_size=settings.EVENT_STREAM_BUFFER_SIZE,
        heartbeat_seconds=settings.EVENT_STREAM_HEARTBEAT_SECONDS,
        max_queue=settings.EVENT_STREAM_MAX_QUEUE,
        signing_key=signing_key,
    )
    return _hub


def get_hub() -> Optional[EventHub]:
    """Return the process-wide hub, or None when the stream is disabled."""
    return _hub


def emit(event_type: str, payload: dict) -> None:
    """Best-effort publish to the hub. Never raises into the caller.

    A no-op when the stream is disabled. Any hub failure is logged and
    swallowed so a revoke/delete operation is never failed by event push.
    """
    hub = get_hub()
    if hub is None:
        return
    try:
        hub.publish(event_type, payload)
    except Exception:  # noqa: BLE001 — push must never break the operation
        logger.exception("auth.event_stream publish failed event_type=%s", event_type)
