"""Prometheus metrics for the auth event-stream bridge.

These live alongside the shared SDK auth metrics (``token_validation_failures_total``
& co.) but are fa-auth-specific, so they are registered here on the same
``auth_sdk_m8.observability.metrics.REGISTRY`` that the ``/metrics`` endpoint
renders. ``setup`` is idempotent — it unregisters any previously created
collectors first — so it is safe to call repeatedly (startup and tests).

When metrics are disabled ``get()`` returns ``None`` and the hub skips every
metric call, exactly like the SDK's own ``observability.metrics`` module.
"""

from typing import Optional

from prometheus_client import Counter, Gauge

from auth_sdk_m8.observability.metrics import REGISTRY


def _norm_prefix(api_prefix: str) -> str:
    """Derive a valid Prometheus name prefix from the API prefix.

    Mirrors the SDK's own prefixing so event-stream metrics share the service
    namespace (e.g. ``user_auth_events_published_total``).
    """
    p = api_prefix.strip().lstrip("/").replace("-", "_").replace("/", "_")
    return f"{p}_" if p else ""


class _EventStreamMetrics:
    """Container for event-stream metric objects."""

    published_total: Counter
    connections: Gauge
    disconnects_total: Counter


_m: Optional[_EventStreamMetrics] = None


def setup(enabled: bool, api_prefix: str) -> None:
    """Register event-stream metrics. Idempotent — safe to call more than once.

    Args:
        enabled: Master switch — when False the metrics are torn down and
            ``get()`` returns None (zero runtime cost in the hub).
        api_prefix: Service API prefix, used as the metric name prefix to match
            the SDK auth metrics namespace.
    """
    global _m
    if _m is not None:
        for collector in (_m.published_total, _m.connections, _m.disconnects_total):
            REGISTRY.unregister(collector)
        _m = None

    if not enabled:
        return

    pfx = _norm_prefix(api_prefix)
    m = _EventStreamMetrics()
    m.published_total = Counter(
        f"{pfx}auth_events_published_total",
        "Auth events fanned out on the SSE bridge by type "
        "(event_type: session-revoked | user-deleted)",
        ["event_type"],
        registry=REGISTRY,
    )
    m.connections = Gauge(
        f"{pfx}auth_event_stream_connections",
        "Currently connected auth event-stream consumers",
        registry=REGISTRY,
    )
    m.disconnects_total = Counter(
        f"{pfx}auth_event_stream_disconnects_total",
        "Event-stream consumer disconnects by cause "
        "(reason: client | backpressure | shutdown)",
        ["reason"],
        registry=REGISTRY,
    )
    _m = m


def get() -> Optional[_EventStreamMetrics]:
    """Return the event-stream metrics container, or None when disabled."""
    return _m
