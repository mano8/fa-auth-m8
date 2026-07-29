"""API key service layer.

Responsibilities:
- Secure key generation and hash verification
- DB lookups for active keys
- Rate limit resolution (per-key → per-user → settings defaults)
- Rate limit enforcement with Redis and Prometheus metrics wiring
"""

import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Iterable, Optional, Union

import sqlalchemy as sa
from redis import Redis
from sqlmodel import Session, col, select

from auth_sdk_m8.observability import metrics as _metrics
from auth_sdk_m8.schemas.base import Period, RoleType
from auth_user_service.core.client import RateLimitResult, RedisRateLimiter
from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience, RateLimit
from auth_user_service.db_models.privileged_action_audit import AuditAction
from auth_user_service.services.audit import (
    _WINDOW_SECONDS,
    _as_aware_utc,
    RetentionWindow,
    record_privileged_action,
)

if TYPE_CHECKING:
    from auth_user_service.core.config import Settings

_logger = logging.getLogger(__name__)

# Ordered from finest to coarsest — enforced in this order so a MINUTE
# burst is caught before checking HOUR, giving the tightest feedback.
_PERIOD_ORDER: list[Period] = [
    Period.MINUTE,
    Period.HOUR,
    Period.DAY,
    Period.MONTH,
]


def _emit_validation_metric(label: str) -> None:
    m = _metrics.get()
    if m and m.api_key_validations_total:
        m.api_key_validations_total.labels(result=label).inc()


def _emit_rate_check_metric(label: str) -> None:
    m = _metrics.get()
    if m and m.api_key_rate_limit_checks_total:
        m.api_key_rate_limit_checks_total.labels(result=label).inc()


def _emit_rate_hit_metric(exceeded_period: Optional[Period]) -> None:
    m = _metrics.get()
    if m and m.api_key_rate_limit_hits_total and exceeded_period:
        m.api_key_rate_limit_hits_total.labels(period=exceeded_period.value).inc()


class ApiKeyPurgeRetentionFloorError(ValueError):
    """Raised when the requested dead-key purge window is below the configured floor.

    The floor (default >= 90 days, ``API_KEY_PURGE_MIN_RETENTION_SECONDS``) is a
    deployment-level setting, not a per-call parameter: shortening it below the
    default is an explicit operator config opt-in, never something a caller of
    the purge action can request directly.
    """


class ApiKeyPurgeStalledError(RuntimeError):
    """Raised when the purge loop selects the same rows twice in a row (G8-10).

    Modelled on :class:`auth_user_service.services.audit.AuditPurgeStalledError`:
    if a delete is silently suppressed, the same eligible rows would otherwise
    be re-selected forever, holding a database session open indefinitely.
    """


@dataclass(frozen=True)
class ApiKeyPurgeResult:
    """Outcome of one dead-key retention-purge run."""

    window: RetentionWindow
    removed: int


class ApiKeyAudienceError(ValueError):
    """A requested audience binding is invalid.

    Raised for a malformed audience (empty/wildcard), an id that is not an
    enabled consumer granted the ``api-key-introspection`` scope, exceeding the
    per-key maximum, or an attempt to change an immutable already-bound set.
    Carries only a caller-safe message — never key material.
    """


class ApiKeyService:
    """Handles creation, validation, and revocation of API keys."""

    KEY_PREFIX = "ak_"

    @staticmethod
    def normalize_audiences(audiences: Iterable[str]) -> list[str]:
        """Canonicalize a requested audience set without checking the registry.

        Strips each id, rejects an empty or wildcard entry, and de-duplicates
        preserving first-seen order so comparisons are exact (``APIKEY-AUD-01``:
        wildcards are forbidden and matching is exact after normalization).

        Raises:
            ApiKeyAudienceError: On an empty or wildcard audience id.
        """
        seen: set[str] = set()
        result: list[str] = []
        for raw in audiences:
            audience = (raw or "").strip()
            if not audience:
                raise ApiKeyAudienceError("An audience id must not be empty.")
            if "*" in audience:
                raise ApiKeyAudienceError("Audience wildcards are not permitted.")
            if audience in seen:
                continue
            seen.add(audience)
            result.append(audience)
        return result

    @classmethod
    def validate_audiences(cls, audiences: Iterable[str]) -> list[str]:
        """Normalize and authorize a requested audience set (``APIKEY-AUD-01``).

        Only an **enabled consumer explicitly granted the
        ``api-key-introspection`` scope** may be named — so a leaked key can never
        be introspected by a consumer that was never permitted to — and no more
        than ``settings.API_KEY_MAX_AUDIENCES`` per key.

        Returns:
            The normalized, authorized audience list.

        Raises:
            ApiKeyAudienceError: On a malformed id, an over-count, or an unknown /
                ineligible consumer.
        """
        # Imported lazily to keep this dependency-light module free of a
        # config/registry import at module load.
        from auth_user_service.core.config import settings
        from auth_user_service.core.consumer_registry import (
            get_introspection_audiences,
        )

        normalized = cls.normalize_audiences(audiences)
        max_count = settings.API_KEY_MAX_AUDIENCES
        if len(normalized) > max_count:
            raise ApiKeyAudienceError(
                f"An API key may bind at most {max_count} audience(s)."
            )
        permitted = get_introspection_audiences()
        unknown = [a for a in normalized if a not in permitted]
        if unknown:
            raise ApiKeyAudienceError(
                "Unknown or ineligible audience(s): " + ", ".join(sorted(unknown))
            )
        return normalized

    @staticmethod
    def set_key_audiences_in_tx(
        session: Session,
        api_key: ApiKey,
        audiences: Iterable[str],
    ) -> list[ApiKeyAudience]:
        """Replace *api_key*'s audience rows with *audiences* (transaction-neutral).

        Deletes any existing bindings and adds one row per id **without
        committing**, so the caller commits atomically with the key row. The
        *audiences* must already be validated (:meth:`validate_audiences`).
        Returns the created rows.

        A newly issued key has no ``id`` yet — the primary key comes from the
        column default, which SQLAlchemy only applies at INSERT time — so the
        parent is flushed first when needed. Without it every binding would
        carry a null ``api_key_id`` and the insert would fail on the NOT NULL
        column. Flushing is transaction-neutral: the caller still owns the
        commit boundary.
        """
        for existing in list(api_key.audiences or []):
            session.delete(existing)
        if api_key.id is None:
            session.add(api_key)
            session.flush()
        now = datetime.now(timezone.utc)
        rows = [
            ApiKeyAudience(api_key_id=api_key.id, audience_id=audience, created_at=now)
            for audience in audiences
        ]
        for row in rows:
            session.add(row)
        return rows

    @classmethod
    def bind_existing_key_audiences(
        cls,
        session: Session,
        api_key: ApiKey,
        audiences: Iterable[str],
    ) -> list[str]:
        """Audited operator path: bind *audiences* to an existing key (§3.12).

        Audiences only — ``access_mode`` is immutable and existing keys are
        ``READ_ONLY``. The set is immutable after issuance, so this:

        * binds when the key currently carries **no** audience (the legacy-key
          migration case), or
        * is an **idempotent no-op** when the identical set is already bound, and
        * **refuses** to change a different non-empty set — rotate the key.

        Transaction-neutral (the caller commits). Returns the normalized bound set.

        Raises:
            ApiKeyAudienceError: On invalid audiences or an immutable-set change.
        """
        normalized = cls.validate_audiences(audiences)
        current = sorted(a.audience_id for a in (api_key.audiences or []))
        if current == sorted(normalized):
            return normalized
        if current:
            raise ApiKeyAudienceError(
                "The key already carries a different audience set; audiences are "
                "immutable after issuance — issue a replacement key instead."
            )
        cls.set_key_audiences_in_tx(session, api_key, normalized)
        return normalized

    @classmethod
    def generate_key(cls) -> tuple[str, str]:
        """Generate a new API key and its SHA-256 hash.

        Returns:
            (plaintext, sha256_hex) — plaintext is shown to the user once
            and never stored; sha256_hex is persisted in the database.
        """
        plaintext = cls.KEY_PREFIX + uuid.uuid4().hex
        key_hash = SecurityHelper.hash_token(plaintext)
        return plaintext, key_hash

    @staticmethod
    def verify_key(plaintext: str, stored_hash: str) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        candidate = SecurityHelper.hash_token(plaintext)
        return secrets.compare_digest(candidate, stored_hash)

    @staticmethod
    def get_active_key(session: Session, plaintext: str) -> Optional[ApiKey]:
        """Look up an API key by plaintext value.

        Increments the api_key_validations_total metric with the appropriate
        result label. Returns None for any non-success outcome.
        """
        key_hash = SecurityHelper.hash_token(plaintext)
        api_key = session.exec(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        ).first()

        if api_key is None:
            _emit_validation_metric("invalid")
            return None

        if api_key.revoked:
            _emit_validation_metric("revoked")
            return None

        now = datetime.now(timezone.utc)
        if api_key.expires_at and api_key.expires_at.replace(tzinfo=timezone.utc) < now:
            _emit_validation_metric("expired")
            return None

        _emit_validation_metric("success")
        return api_key

    @staticmethod
    def revoke_key_in_tx(session: Session, api_key: ApiKey) -> None:
        """Authoritatively revoke a single API key (transaction-neutral, 3.11).

        Flips ``revoked`` on the row in memory and does **not** commit, so the
        caller owns the commit boundary — used both by the owner's own revoke
        route and the limited superadmin revoke surface, where the ``delete``
        audit row must land in the **same** transaction as the revocation. An
        API key is a bearer pointer resolved live against its owner, so setting
        ``revoked=True`` on the authoritative row *is* the delete-equivalent
        revocation: the key is rejected on its next use in every token mode.
        """
        api_key.revoked = True
        session.add(api_key)

    @staticmethod
    def revoke_all_user_keys_in_tx(session: Session, user_id: uuid.UUID) -> int:
        """Mark every non-revoked API key owned by *user_id* as revoked (3.11).

        Transaction-neutral: it flips ``revoked`` on the owner's keys in memory
        and does **not** commit, so the route-owned deactivation transaction
        revokes the keys atomically with the ``is_active=false`` write and the
        generation bump. Reactivation never clears ``revoked`` — an
        incident-response deactivation must not silently re-arm possibly
        compromised credentials — so this is only ever called on deactivation.
        Returns the number of keys revoked.
        """
        keys = session.exec(
            select(ApiKey).where(
                ApiKey.user_id == user_id,
                ApiKey.revoked == False,  # noqa: E712
            )
        ).all()
        for key in keys:
            key.revoked = True
            session.add(key)
        return len(keys)

    @staticmethod
    def get_limits(
        session: Session,
        api_key_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> list[tuple[Period, int]]:
        """Resolve rate limits for a key using the priority chain.

        Priority: per-key RateLimit rows > per-user RateLimit rows.
        Falls back to an empty list (caller uses settings defaults).
        Returns periods in _PERIOD_ORDER order.
        """
        stmt = select(RateLimit).where(
            (RateLimit.api_key_id == api_key_id) | (RateLimit.user_id == user_id)
        )
        rows = session.exec(stmt).all()

        # Build a dict: period → (limit, is_key_specific)
        resolved: dict[Period, tuple[int, bool]] = {}
        for row in rows:
            is_key = row.api_key_id == api_key_id
            period = row.period
            existing = resolved.get(period)
            if existing is None or (is_key and not existing[1]):
                # Key-specific overrides user-level defaults
                resolved[period] = (row.limit, is_key)

        return [(p, resolved[p][0]) for p in _PERIOD_ORDER if p in resolved]


class RateLimitEnforcer:
    """Enforces rate limits using Redis counters and emits Prometheus metrics."""

    def __init__(self, redis: Redis, settings: "Settings") -> None:  # type: ignore[name-defined]
        self._limiter = RedisRateLimiter(redis)
        self._settings = settings

    def enforce(
        self,
        api_key: ApiKey,
        limits: list[tuple[Period, int]],
    ) -> RateLimitResult:
        """Check all rate limit windows and emit metrics.

        Increments checks_total BEFORE branching so the ratio
        allowed / checks_total remains stable on exception paths.

        Args:
            api_key: The validated API key.
            limits: Per-period limits from ApiKeyService.get_limits().
                    Falls back to settings defaults when empty.

        Returns:
            RateLimitResult — callers raise 429 when result.allowed is False.
        """
        # Resolve effective limits (DB overrides → settings defaults)
        effective = limits or self._default_limits()

        # Increment checks_total before branching (invariant: checks >= allowed + blocked)
        _emit_rate_check_metric("checked")

        result = self._limiter.check_all_limits(api_key.id, effective)

        if result.allowed:
            _emit_rate_check_metric("allowed")
        else:
            _emit_rate_check_metric("blocked")
            _emit_rate_hit_metric(result.exceeded_period)
            ref = str(api_key.id)
            _logger.warning(
                "ratelimit.blocked ref=%s period=%s",
                ref,
                result.exceeded_period,
            )

        return result

    def _default_limits(self) -> list[tuple[Period, int]]:
        """Return settings-based default limits for all configured periods."""
        s = self._settings
        limits = []
        if s.API_KEY_DEFAULT_LIMIT_MINUTE > 0:
            limits.append((Period.MINUTE, s.API_KEY_DEFAULT_LIMIT_MINUTE))
        if s.API_KEY_DEFAULT_LIMIT_HOUR > 0:
            limits.append((Period.HOUR, s.API_KEY_DEFAULT_LIMIT_HOUR))
        if s.API_KEY_DEFAULT_LIMIT_DAY > 0:
            limits.append((Period.DAY, s.API_KEY_DEFAULT_LIMIT_DAY))
        if s.API_KEY_DEFAULT_LIMIT_MONTH > 0:
            limits.append((Period.MONTH, s.API_KEY_DEFAULT_LIMIT_MONTH))
        return limits


def purge_dead_api_keys(
    session: Session,
    *,
    window: RetentionWindow,
    actor_user_id: Union[uuid.UUID, str],
    actor_role: RoleType,
    batch_size: Optional[int] = None,
    now: Optional[datetime] = None,
) -> ApiKeyPurgeResult:
    """Bulk-delete dead ``ApiKey`` rows older than *window* (``APIKEY-LIFECYCLE-01``).

    Modelled directly on :func:`auth_user_service.services.audit.purge_expired_audit_rows`.
    A key is *dead* when it is revoked (dated by ``updated_at``, which stops
    advancing once revocation happens because the ``last_used_at``
    write-behind no longer touches it) or when it carries a non-null
    ``expires_at`` in the past (``expires_at IS NULL`` never qualifies on the
    expiry basis). Enforces the configured minimum-retention floor
    (``API_KEY_PURGE_MIN_RETENTION_SECONDS``, a dedicated floor separate from
    the audit table's) before touching any row: a *window* shorter than the
    floor raises :class:`ApiKeyPurgeRetentionFloorError` and deletes nothing.

    The purge unit is the parent ``ApiKey`` row, never an audience row alone —
    deleting it lets the existing ``ON DELETE CASCADE`` clear its
    ``api_key_audiences`` and ``RateLimit`` children in the same operation.
    Rows are claimed in ``API_KEY_PURGE_BATCH_SIZE``-row batches with
    ``FOR UPDATE SKIP LOCKED``, each batch committed before the next is
    claimed, so a large purge never holds one long-lived lock over the key
    table.

    There is deliberately no key-id/owner-id/row-scoping parameter — the
    horizon is the only selector, so this can never become a targeted
    single-row delete.

    Once the sweep completes, the purge writes **its own** privileged-action
    audit row via :func:`record_privileged_action` (actor, window, and the
    removed-row count packed into ``row_pk``), timestamped *now* — always
    newer than the horizon it was just computed from — so it survives this
    and every subsequent purge.

    Args:
        session: DB session; each batch commit is on this session.
        window: The chosen retention window.
        actor_user_id: Id of the authenticated superadmin performing the purge.
        actor_role: The actor's role snapshot, from the authenticated principal.
        batch_size: Rows per delete batch; defaults to
            ``settings.API_KEY_PURGE_BATCH_SIZE``.
        now: Override for the current time (tests only); defaults to the
            actual current UTC time.

    Returns:
        :class:`ApiKeyPurgeResult` with the window and the total rows removed.

    Raises:
        ApiKeyPurgeRetentionFloorError: *window* is shorter than the
            configured floor.
    """
    from auth_user_service.core.config import settings

    window_seconds = _WINDOW_SECONDS[window]
    floor_seconds = settings.API_KEY_PURGE_MIN_RETENTION_SECONDS
    if window_seconds < floor_seconds:
        raise ApiKeyPurgeRetentionFloorError(
            f"retention window {window.value!r} ({window_seconds}s) is below "
            f"the configured minimum-retention floor ({floor_seconds}s); "
            "lowering the floor requires an explicit operator config change"
        )

    batch = batch_size or settings.API_KEY_PURGE_BATCH_SIZE
    current = _as_aware_utc(now or datetime.now(timezone.utc))
    horizon = current - timedelta(seconds=window_seconds)

    dead_predicate = sa.or_(
        sa.and_(col(ApiKey.revoked).is_(True), col(ApiKey.updated_at) < horizon),
        sa.and_(
            col(ApiKey.expires_at).is_not(None),
            col(ApiKey.expires_at) < horizon,
        ),
    )

    removed = 0
    previous_ids: Optional[frozenset] = None
    while True:
        rows = session.exec(
            select(ApiKey)
            .where(dead_predicate)
            .order_by(col(ApiKey.id))
            .limit(batch)
            .with_for_update(skip_locked=True)
        ).all()
        if not rows:
            break
        ids = frozenset(row.id for row in rows)
        if previous_ids is not None and ids == previous_ids:
            raise ApiKeyPurgeStalledError(
                "api-key purge made no progress: the same "
                f"{len(ids)} row(s) were re-selected after a commit — deletes "
                "are being silently suppressed"
            )
        for row in rows:
            session.delete(row)
        session.commit()
        removed += len(rows)
        if len(rows) < batch:
            break
        previous_ids = ids

    record_privileged_action(
        session,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        action=AuditAction.DELETE,
        table_name=ApiKey.__tablename__,
        row_pk=f"retention_purge:window={window.value}:removed={removed}",
        target_owner_id=None,
    )
    session.commit()
    return ApiKeyPurgeResult(window=window, removed=removed)
