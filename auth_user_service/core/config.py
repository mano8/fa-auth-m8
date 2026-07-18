"""
Configuration settings for the FastAPI application.
This module loads environment settings securely and applies best practices.
"""

from pathlib import Path
from typing import Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict
from auth_sdk_m8.utils.paths import find_dotenv
from auth_sdk_m8.core.config import CommonSettings
from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin
# pylint: disable=invalid-name, import-outside-toplevel


class ConsumerCredentialConfig(BaseModel):
    """One per-consumer private-API credential, as supplied via configuration.

    Used by the Phase 9.1 issuer side (``PRIVATE_API_CONSUMERS``): the issuer
    replaces the single shared ``PRIVATE_API_SECRET`` with a map of consumer ids
    → scoped per-consumer secrets. ``secret`` is either the plaintext bootstrap
    secret (dev convenience) or the portable ``sha256$<salt_hex>$<digest_hex>``
    encoded form (production — hashed at rest, never plaintext on disk); the
    loader auto-detects which by the ``sha256$`` prefix. ``scopes`` are
    deny-by-default — a consumer is refused every private operation until granted
    one (``introspection`` / ``event-stream`` / ``user-create``, or a custom
    string). See :mod:`auth_user_service.core.consumer_registry`.
    """

    model_config = ConfigDict(extra="forbid")

    secret: SecretStr
    scopes: list[str] = Field(default_factory=list)


class Settings(ObservabilitySettingsMixin, CommonSettings):
    """Settings for the auth_user_service: adds only new fields.

    Secret sourcing (the Docker/K8s ``<FIELD>_FILE`` convention) is inherited
    from :class:`auth_sdk_m8.core.config.CommonSettings` — this service does not
    re-implement it. For any field ``FOO`` (service-declared *or* inherited), if
    ``FOO_FILE`` points at a readable file its stripped contents become the value
    of ``FOO``, outranking a plaintext ``.env``/env value (init kwargs still win).
    The production overlay relies on this to mount runtime secrets under
    ``/run/secrets/*`` instead of inlining them. Locked in by
    ``tests/security/test_config_file_secrets.py`` (plan item 6.1)."""

    # Override env file directory if necessary
    ENV_FILE_DIR = Path(__file__).resolve().parent

    # Pydantic v2 config must be a plain class attribute (no annotation)
    model_config = SettingsConfigDict(
        env_file=find_dotenv(ENV_FILE_DIR),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
    )

    # Extend validation lists
    required_fields = CommonSettings.required_fields
    secret_fields = CommonSettings.secret_fields + [
        "FIRST_SUPERUSER",
        "FIRST_SUPERUSER_PASSWORD",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "PRIVATE_API_SECRET",
        "SESSION_SECRET",
        "TOKENS_ENCRYPTION_KEY",
        "TOKENS_ENCRYPTION_KEY_OLD",
        "METRICS_SCRAPE_CREDENTIAL",
        "HEALTH_DETAIL_CREDENTIAL",
        # Holds per-consumer bootstrap secrets (plaintext or hashed); keep it out
        # of the debug dump. The strength/changethis validators skip it safely
        # (it is a mapping, not a SecretStr).
        "PRIVATE_API_CONSUMERS",
    ]
    passwords = CommonSettings.passwords + ["FIRST_SUPERUSER_PASSWORD"]
    secret_keys = CommonSettings.secret_keys + [
        "PRIVATE_API_SECRET",
        "SESSION_SECRET",
        "TOKENS_ENCRYPTION_KEY",
        # Strength-validated only when set (None is skipped); the previous key is
        # itself a real secret, so it must clear the same bar as the current one.
        "TOKENS_ENCRYPTION_KEY_OLD",
    ]
    TABLES_PREFIX: str = "auth"

    # Number of trusted reverse-proxy hops in front of this service.
    # Used to select the real client IP from X-Forwarded-For by taking
    # xff[-TRUSTED_PROXY_COUNT] (Nth entry from the right, 1-indexed, since
    # Traefik appends the peer IP). Must be >= 0.
    # Set to 1 when a single Traefik instance sits in front.
    TRUSTED_PROXY_COUNT: int = 1

    @field_validator("TRUSTED_PROXY_COUNT")
    @classmethod
    def _validate_proxy_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("TRUSTED_PROXY_COUNT must be >= 0")
        return v

    # Coarse per-source-IP login cap, shared across all accounts. Catches a
    # credential-spray that rotates the username every attempt (which evades
    # the per-email LOGIN_RATE_LIMIT_REQUESTS counter). Set higher than the
    # per-email limit to tolerate shared NAT / office egress IPs. Reuses the
    # per-email window (LOGIN_RATE_LIMIT_WINDOW_MINUTES). Defined here rather
    # than in the shared SDK so this hardening ships without an SDK release.
    LOGIN_IP_RATE_LIMIT_REQUESTS: int = Field(50, ge=1, le=100000)

    # ── Auth event stream (fa-auth SSE bridge) ───────────────────────────────
    # fa-auth bridges its own auth-state events (session revoked / user deleted)
    # to backend consumers over an authenticated SSE stream on the existing
    # private API. Push is a best-effort cache-eviction accelerator — the JTI
    # blacklist (jti-status) remains the revocation authority — so a disabled or
    # unreachable stream never changes correctness. Payloads are HMAC-signed with
    # the shared EVENT_SIGNING_KEY (reused, already boot-required).
    EVENT_STREAM_ENABLED: bool = True
    # Ring-buffer depth for Last-Event-ID resume. A reconnecting consumer whose
    # last id is still buffered replays exactly the missed events; once evicted
    # the server signals an unresumable gap and the consumer flushes its caches.
    EVENT_STREAM_BUFFER_SIZE: int = Field(256, ge=1, le=100000)
    # Heartbeat comment frame interval (seconds). Keeps the connection alive
    # through reverse proxies and lets a consumer detect a dead stream. Must be
    # comfortably below the consumer read timeout.
    EVENT_STREAM_HEARTBEAT_SECONDS: float = Field(15.0, gt=0, le=300)
    # Per-connection outbound queue depth before a slow consumer is disconnected
    # (it reconnects and resumes/flushes). Never blocks the emitting request.
    EVENT_STREAM_MAX_QUEUE: int = Field(64, ge=1, le=100000)

    # ── Revocation outbox worker (3.5.2) ────────────────────────────────────
    # Role-change revocation side effects (Redis blacklist + user-wide v2 event)
    # are committed as durable outbox rows atomically with the DB revocation, then
    # drained here with at-least-once delivery. The DB delete is already the
    # authoritative revocation (3.5.4), so a disabled/lagging worker only slows
    # cache eviction — it never changes correctness.
    OUTBOX_WORKER_ENABLED: bool = True
    # How often the in-process drain loop wakes to claim and deliver a batch.
    OUTBOX_DRAIN_INTERVAL_SECONDS: float = Field(1.0, gt=0, le=3600)
    # Max rows claimed per drain (FOR UPDATE SKIP LOCKED).
    OUTBOX_BATCH_SIZE: int = Field(50, ge=1, le=10000)
    # Lease duration on a claimed row; an expired lease is re-claimable so a
    # crashed worker's in-flight rows recover without an alternative claim path.
    OUTBOX_LEASE_SECONDS: int = Field(30, ge=1, le=86400)
    # Delivery attempts before a row is dead-lettered (status='dead').
    OUTBOX_MAX_ATTEMPTS: int = Field(5, ge=1, le=100)
    # Exponential-backoff base and cap (seconds) between retries.
    OUTBOX_BACKOFF_BASE_SECONDS: float = Field(2.0, gt=0, le=3600)
    OUTBOX_BACKOFF_CAP_SECONDS: float = Field(300.0, gt=0, le=86400)
    # How long a completed row is retained (idempotency window) before reaping.
    OUTBOX_COMPLETED_RETENTION_SECONDS: int = Field(3600, ge=0, le=2592000)

    # Optional static scoped credential for scraping {API_PREFIX}/metrics (1.4).
    # Metrics are internal-only by default — the network boundary (internal
    # entrypoint) is the control and this stays unset. Set it only when metrics
    # must cross a less-trusted boundary: requests must then present
    # ``Authorization: Bearer <credential>`` (constant-time match via
    # auth_sdk_m8.security.guards.make_scrape_credential_guard), mapping onto
    # Prometheus ``authorization`` in scrape_configs. Deliberately a long-lived
    # static credential — short-TTL tokens are awkward for a scraper.
    METRICS_SCRAPE_CREDENTIAL: Optional[SecretStr] = None

    # Dedicated credential for the deep-/health detail gate (plan item 9.3).
    # When set, the X-Internal-Token header is matched against this value
    # (constant-time via make_internal_token_authorizer) to reveal the full
    # infrastructure detail body; anonymous callers always get a shallow
    # {"status":...} only. When unset the gate fails closed — no detail body
    # is ever revealed regardless of any presented token.
    # Must be a separate secret from PRIVATE_API_SECRET (the validator rejects
    # reuse); rotate independently without touching the private-API consumer
    # credentials. HEALTH_DETAIL_FILE is also supported for Docker/K8s secrets.
    HEALTH_DETAIL_CREDENTIAL: Optional[SecretStr] = None

    @model_validator(mode="after")
    def _assert_no_operational_secret_reuse(self) -> "Settings":
        """Fail closed if an operational credential reuses PRIVATE_API_SECRET."""
        private = self.PRIVATE_API_SECRET.get_secret_value()
        if (
            self.HEALTH_DETAIL_CREDENTIAL is not None
            and self.HEALTH_DETAIL_CREDENTIAL.get_secret_value() == private
        ):
            raise ValueError(
                "HEALTH_DETAIL_CREDENTIAL must not equal PRIVATE_API_SECRET — "
                "operational credentials must be separately rotatable (plan 9.3)"
            )
        if (
            self.METRICS_SCRAPE_CREDENTIAL is not None
            and self.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == private
        ):
            raise ValueError(
                "METRICS_SCRAPE_CREDENTIAL must not equal PRIVATE_API_SECRET — "
                "operational credentials must be separately rotatable (plan 9.3)"
            )
        return self

    @model_validator(mode="after")
    def _require_consumers_in_prod_strict(self) -> "Settings":
        """Fail startup when production or strict mode has an empty PRIVATE_API_CONSUMERS.

        The legacy single-secret private-API gate is retired (v1.0.0). With no
        per-consumer registry, every /private/* call fails closed (401) and the
        service-token exchange is unavailable. In development this is a loud
        misconfiguration warning; in production/strict it is a deployment fault
        that must prevent startup (plan 11.2a).

        Permitted modes:
        - ENVIRONMENT != "production" AND STRICT_PRODUCTION_MODE=False AND
          AUTH_STRICT_MODE=False → warning at runtime, no startup failure.
        - Any production/strict condition → startup raises here.
        """
        is_prod_or_strict = (
            self.ENVIRONMENT == "production"
            or self.STRICT_PRODUCTION_MODE
            or self.AUTH_STRICT_MODE
        )
        if is_prod_or_strict and not self.PRIVATE_API_CONSUMERS:
            raise ValueError(
                "PRIVATE_API_CONSUMERS is required in production/strict mode "
                "(ENVIRONMENT=production, STRICT_PRODUCTION_MODE=true, or "
                "AUTH_STRICT_MODE=true). Mount the registry via "
                "PRIVATE_API_CONSUMERS_FILE=/run/secrets/private_api_consumers.json "
                "or set PRIVATE_API_CONSUMERS directly. "
                "Without this every /private/* call is rejected (401) and the "
                "service-token exchange is unavailable — this is a deployment fault, "
                "not a safe runtime mode."
            )
        return self

    # API key rate limiting defaults (0 = disabled for that period)
    # API_KEY_STRICT_RATE_LIMIT is an explicit opt-in, but production/strict
    # deployments inherit strict behaviour regardless — see
    # effective_api_key_strict_rate_limit below (plan 11.3).
    API_KEY_STRICT_RATE_LIMIT: bool = False
    API_KEY_DEFAULT_LIMIT_MINUTE: int = 60
    API_KEY_DEFAULT_LIMIT_HOUR: int = 1_000
    API_KEY_DEFAULT_LIMIT_DAY: int = 10_000
    API_KEY_DEFAULT_LIMIT_MONTH: int = 200_000
    API_KEY_MAX_PER_USER: int = 10
    # Maximum introspection audiences bindable to a single API key (APIKEY-AUD-01,
    # §3.12). Bounds the blast radius of one key across services; operational
    # guidance still recommends one key per integration.
    API_KEY_MAX_AUDIENCES: int = Field(3, ge=1, le=50)

    # Per-consumer anti-abuse ceiling for POST /private/v1/api-keys/introspect
    # (§3.12 step 3), consumed on every authenticated attempt — separate from and
    # in addition to the introspected key's own functional quota. A fixed
    # per-minute window keyed by the authenticated consumer id bounds how fast a
    # single (compromised or buggy) internal consumer can probe keys, without
    # ever touching the per-key counters. Observed with bounded labels only (the
    # consumer id is a small registry-bounded set — never a JTI/key hash/user id).
    API_KEY_INTROSPECTION_ANTIABUSE_PER_MINUTE: int = Field(600, ge=1, le=1_000_000)

    @property
    def effective_api_key_strict_rate_limit(self) -> bool:
        """Whether API-key verification must fail closed when Redis is unavailable.

        API-key rate limiting is a Redis-backed abuse control. When Redis is
        down a valid key would otherwise be admitted with no minute/hour/day
        ceiling. Strict behaviour refuses the key with 503 instead. It is active
        when explicitly opted in via ``API_KEY_STRICT_RATE_LIMIT`` **or** implied
        by any production/strict posture — ``AUTH_STRICT_MODE`` (which forces
        every Redis-dependent control fail-closed), ``ENVIRONMENT=production`` or
        ``STRICT_PRODUCTION_MODE``. Only non-production, non-strict development
        stays fail-open, and that admission is logged as unsafe (plan 11.3).
        """
        return (
            self.API_KEY_STRICT_RATE_LIMIT
            or self.AUTH_STRICT_MODE
            or self.ENVIRONMENT == "production"
            or self.STRICT_PRODUCTION_MODE
        )

    # Declare only service-specific fields
    FIRST_SUPERUSER: EmailStr
    FIRST_SUPERUSER_PASSWORD: SecretStr
    GOOGLE_CLIENT_ID: Optional[SecretStr] = None
    GOOGLE_CLIENT_SECRET: Optional[SecretStr] = None
    # Fixed backend callback URI — must match Google Console exactly.
    # Never auto-generated from request host to prevent host-spoofing.
    GOOGLE_OAUTH_REDIRECT_URI: str = ""
    PRIVATE_API_SECRET: SecretStr
    # ── Per-consumer private-API credentials (Phase 9.1, issuer side) ─────────
    # Map of consumer id → {secret, scopes}. This is now the **only** private-API
    # auth model: each consumer presents X-Internal-Client + X-Internal-Token (or a
    # short-TTL service token) and is authorized only for the scopes it was granted
    # (deny-by-default), bounding the blast radius to one consumer. The legacy
    # single shared PRIVATE_API_SECRET gate has been **retired** (v1.0.0): when this
    # map is empty every /private/* call fails closed (401) and the service-token
    # exchange is disabled (404) — startup logs the misconfiguration. It must be set
    # for any inter-service traffic. PRIVATE_API_SECRET stays required: it signs the
    # short-TTL service tokens minted at {API_PREFIX}/private/v1/service-token and
    # backs /health detail-gating + /metrics (1.4). Supply as a JSON object, e.g.
    #   PRIVATE_API_CONSUMERS='{"media-service":{"secret":"sha256$..","scopes":["introspection"]}}'
    PRIVATE_API_CONSUMERS: dict[str, ConsumerCredentialConfig] = Field(
        default_factory=dict
    )
    # Lifetime (seconds) of a minted short-TTL scoped service token. Rotation
    # comes from the short TTL; the per-consumer bootstrap secret rotates rarely.
    SERVICE_TOKEN_TTL_SECONDS: int = Field(300, ge=30, le=3600)
    # Dedicated signing key for the Starlette session cookie. Kept separate
    # from TOKENS_ENCRYPTION_KEY (key separation): rotating the session key
    # must not invalidate encrypted external tokens, and vice versa.
    # NOTE on SESSION_SECRET rotation (plan item 6.2-pre decision): the Starlette
    # SessionMiddleware exposes a single ``secret_key`` with no native key-list, so
    # SESSION_SECRET has no dual-key fallback. The decision is to **accept the
    # bounded re-auth window** rather than ship a custom fallback-capable signer:
    # the session cookie's ``max_age=3600`` (main.py) caps the blast radius of a
    # rotation to ≤1h of stale cookies (holders simply re-authenticate). The 6.2
    # rotation playbook documents SESSION_SECRET as a single-key rotation with this
    # ≤1h re-auth window; no code change is required here.
    SESSION_SECRET: SecretStr
    TOKENS_ENCRYPTION_KEY: SecretStr
    # Previous TOKENS_ENCRYPTION_KEY, set only during a no-downtime key rotation
    # (plan item 6.2-pre). When present, external OAuth tokens persisted under the
    # old key remain decryptable via the SecurityHelper MultiFernet new→old
    # fallback while new writes use TOKENS_ENCRYPTION_KEY. Remove it once every
    # stored token has been re-encrypted under (or has expired past) the new key.
    TOKENS_ENCRYPTION_KEY_OLD: Optional[SecretStr] = None


try:
    settings = Settings()
except Exception as e:
    # Raise with a clear error message if validation fails.
    raise RuntimeError(f"Configuration validation error:\n {str(e)}") from e

if __name__ == "__main__":
    # For debugging, print out public settings without exposing secrets.
    public_settings = settings.model_dump()
    for field in settings.secret_fields:
        public_settings.pop(field, None)
    print(public_settings)
