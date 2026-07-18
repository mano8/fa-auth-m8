"""Prometheus metrics for revocation-propagation via the transactional outbox.

These sit alongside the shared SDK auth metrics and the event-stream metrics on
``auth_sdk_m8.observability.metrics.REGISTRY`` (rendered by ``/metrics``), but are
fa-auth-specific. ``setup`` is idempotent — it unregisters any previously created
collectors first — so it is safe to call repeatedly (startup and tests). When
disabled, ``get()`` returns ``None`` and every emit helper no-ops, exactly like
the SDK's own ``observability.metrics`` module.

JTIs and other opaque secrets are **never** used as label values (3.5.2); only
the low-cardinality ``effect_type`` (``blacklist`` | ``publish``) is a label.
"""

from typing import Optional

from prometheus_client import Counter, Histogram

from auth_sdk_m8.observability.metrics import REGISTRY


def _norm_prefix(api_prefix: str) -> str:
    """Derive a valid Prometheus name prefix from the API prefix.

    Mirrors the SDK's own prefixing so outbox metrics share the service
    namespace (e.g. ``user_revocation_outbox_effects_total``).
    """
    p = api_prefix.strip().lstrip("/").replace("-", "_").replace("/", "_")
    return f"{p}_" if p else ""


class _OutboxMetrics:
    """Container for revocation-outbox metric objects."""

    enqueued_total: Counter
    completed_total: Counter
    retried_total: Counter
    dead_total: Counter
    propagation_seconds: Histogram


_m: Optional[_OutboxMetrics] = None


def setup(enabled: bool, api_prefix: str) -> None:
    """Register revocation-outbox metrics. Idempotent — safe to call repeatedly.

    Args:
        enabled: Master switch — when False the metrics are torn down and
            ``get()`` returns None (zero runtime cost on the drain path).
        api_prefix: Service API prefix, used as the metric name prefix to match
            the SDK auth metrics namespace.
    """
    global _m
    if _m is not None:
        for collector in (
            _m.enqueued_total,
            _m.completed_total,
            _m.retried_total,
            _m.dead_total,
            _m.propagation_seconds,
        ):
            REGISTRY.unregister(collector)
        _m = None

    if not enabled:
        return

    pfx = _norm_prefix(api_prefix)
    m = _OutboxMetrics()
    m.enqueued_total = Counter(
        f"{pfx}revocation_outbox_enqueued_total",
        "Revocation outbox effects enqueued in a role-change transaction by type "
        "(effect_type: blacklist | publish)",
        ["effect_type"],
        registry=REGISTRY,
    )
    m.completed_total = Counter(
        f"{pfx}revocation_outbox_completed_total",
        "Revocation outbox effects successfully delivered by type",
        ["effect_type"],
        registry=REGISTRY,
    )
    m.retried_total = Counter(
        f"{pfx}revocation_outbox_retried_total",
        "Revocation outbox effect deliveries that failed and were rescheduled",
        ["effect_type"],
        registry=REGISTRY,
    )
    m.dead_total = Counter(
        f"{pfx}revocation_outbox_dead_total",
        "Revocation outbox effects that exhausted retries (dead-letter)",
        ["effect_type"],
        registry=REGISTRY,
    )
    m.propagation_seconds = Histogram(
        f"{pfx}revocation_outbox_propagation_seconds",
        "Seconds from outbox enqueue (commit) to successful effect delivery",
        ["effect_type"],
        registry=REGISTRY,
    )
    _m = m


def get() -> Optional[_OutboxMetrics]:
    """Return the outbox metrics container, or None when disabled."""
    return _m


def record_enqueued(effect_type: str, count: int = 1) -> None:
    """Count effects enqueued in a committed role-change transaction."""
    if _m is not None and count:
        _m.enqueued_total.labels(effect_type=effect_type).inc(count)


def record_completed(effect_type: str, propagation_seconds: Optional[float]) -> None:
    """Count a delivered effect and, when known, observe its propagation latency."""
    if _m is None:
        return
    _m.completed_total.labels(effect_type=effect_type).inc()
    if propagation_seconds is not None and propagation_seconds >= 0:
        _m.propagation_seconds.labels(effect_type=effect_type).observe(
            propagation_seconds
        )


def record_retried(effect_type: str) -> None:
    """Count a retryable delivery failure (rescheduled with backoff)."""
    if _m is not None:
        _m.retried_total.labels(effect_type=effect_type).inc()


def record_dead(effect_type: str) -> None:
    """Count an effect that exhausted its retries (dead-letter)."""
    if _m is not None:
        _m.dead_total.labels(effect_type=effect_type).inc()
