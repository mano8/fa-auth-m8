# Changelog

All notable changes to `fa-auth-m8` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

> Versions correspond to git tags. Earlier drafts carried two mis-numbered
> entries (`0.10.0`, `0.11.0`) that predated the `0.9.0` release by date; they
> have been folded back onto the real `0.8.x` line (`0.8.3`, `0.8.4`) so the
> history descends monotonically and matches the tags and the codebase (`0.9.6`).

---

## [Unreleased]

### Added

- **Deployment security preflight** (`examples/docker_compose/shared/scripts/preflight-security.sh`)
  — a fail-closed gate run from `init-common.sh` before the crypto lifecycle. It
  scans a stack's env and compose files and blocks startup on leftover
  `changethis` placeholders, empty passwords, reused high-value secrets, default
  Vault/Grafana credentials, public `API_BIND_IP` in production, docs flags
  enabled in production, and `:latest` image tags in hardened/production stacks.
  Risky security flags (`EVENT_SIGNING_ENABLED`, `TOKEN_STRICT_VALIDATION`,
  `ACCESS_REVOCATION_FAILURE_MODE`) warn outside strict mode and hard-fail under
  `STRICT_PRODUCTION_MODE`. Fully covered by adversarial unit tests
  (`tests/security/test_preflight_security.py`).
- Per-stack `test.env.example` describing the `security-tests-m8` live
  configuration, a shared `shared_live_tests` harness (pytest config, conftest,
  full-security suite, README), and the shared Alembic migration set used to
  bring a hardened stack up for live runs.
- `grafana.env.example` placeholder per stack.
- `METRICS_SCRAPE_CREDENTIAL` setting (optional `SecretStr`, default unset) on the
  service `Settings`, registered as a masked `secret_fields` entry and documented
  (commented) in the metrics-enabled `auth.env.example` stacks (`hardened_m8`,
  `metrics_m8`). Drives the optional `/metrics` scrape guard (plan item 1.4).

### Changed

- Grafana admin credentials moved out of the committed
  `grafana/config.monitoring` into a gitignored `grafana.env` loaded via
  `env_file`. Pinned the `fa-auth-m8` image to `0.9.8` (was `:latest`) in the
  hardened and vault example stacks.
- Lowered the `redis` requirement floor to `>=5.3.1` to match the tested
  runtime; no security advisory requires the 8.x line.

### Fixed

- Typed the redis sync client responses (`get`/`getdel`/`incr`) in
  `auth_user_service/core/client.py` so `mypy auth_user_service` is clean.

### Security

- **Proxy-independent app-layer protection for `/health` and `/metrics`** (plan
  item 1.4). The deep `{API_PREFIX}/health/` route now answers a shallow
  `{"status": ...}` to every caller and reveals the full infrastructure detail
  (token mode, Redis/DB reachability, circuit breaker, degradation modes) **only**
  to internal callers presenting the `X-Internal-Token` shared secret
  (`PRIVATE_API_SECRET`). `{API_PREFIX}/metrics` gains an optional static scoped
  scrape credential (`METRICS_SCRAPE_CREDENTIAL`): unset keeps metrics
  internal-only (the network boundary is the control); when set, scrapers must
  send `Authorization: Bearer <credential>` (constant-time match) or get `401`.
  Both guards reuse the shared `auth_sdk_m8.security.guards` primitives
  (`make_internal_token_authorizer`, `make_scrape_credential_guard`), so the
  guarantee lives at the app layer and survives a reverse-proxy swap; proxy
  route-hiding stays defense-in-depth. `{API_PREFIX}/ping` remains the
  dependency-free public liveness route. Covered by
  `tests/routes/health_test.py` (detail gating) and
  `tests/security/test_metrics_scrape_guard.py`.
- Removed a hardcoded Grafana admin password from version control.
- **Removed the Docker socket from the hardened example** (plan item 0.3). The
  `hardened_m8` Traefik service no longer mounts `/var/run/docker.sock`, and the
  Docker provider is dropped from `traefik/traefik.yml` in favour of the file
  provider only. Mounting the socket — even read-only — exposes the Docker API,
  which is equivalent to host root. Routing was already declared statically in
  `traefik/dynamic_conf.yml` (backends resolved by container-name DNS over
  `app_net`), so the vestigial `traefik.enable` labels on `auth_user_service` and
  `fastapi_full` were removed too. Public routes are unchanged. Dev examples keep
  the Docker provider.

---

## [0.9.8] — 2026-06-16 · Standard `/meta` + `/ping` routes (issuer)

> **Requires `auth-sdk-m8 >= 1.4.0`** — uses `mount_service_meta` + `ServiceMeta`.

### Added

- **`GET {API_PREFIX}/meta`** (e.g. `/user/meta`) — static, cacheable service
  identity (`service`/`version`/`api_version`/`contract`) read by clients pre-auth
  to assert compatibility; satisfies `@fa-m8/astro-auth-m8`'s
  `assertFaAuthM8Compatibility`. The issuer mounts the shared auth-sdk-m8 routes
  directly (it builds its own app, not via `fastapi_m8.create_app`).
- **`GET /ping`** — prefix-independent, dependency-free liveness (`{"status": "ok"}`).
- `auth_user_service/core/service_meta.py` — `build_service_meta()` plus the
  contract constants (`fa-auth-m8`, contract `0.9`, range `>=0.9.8 <0.10.0` — the
  lower bound is the first release that exposes the discovery routes), kept in
  sync with the astro plugin. Service version tracks `__version__`.

Both routes are kept **separate from the dependency-aware `/health`** (readiness).

---

## [0.9.7] — 2026-06-13 · `tenant_id` token claim

### Added

- **`tenant_id` claim plumbed through token issuance** — new nullable, indexed
  `tenant_id` (UUID) column on the `User` model (`auth_user_service/db_models/users.py`).
  No `Tenant` table, FK, or registration/schema change: new users default to `None` and the
  tenant is set out-of-band (DB/admin). `AuthController.create_auth_tokens` now stamps
  `tenant_id=str(user.tenant_id) if user.tenant_id else None` into `TokenAccessData`, so the
  claim flows through both login and refresh into every issued access token (`None` when unset).
  Schema migration is autogenerated on deploy (docker-compose), not hand-written.
- **`auth-sdk-m8 ≥ 1.3.0`** bump in `requirements_base.txt` — required for the SDK's new
  `tenant_id` field on `UserPayloadData`/`UserModel` that carries and coerces the claim.

---

## [0.9.6] — 2026-06-12 · Auth-event SSE bridge (SB)

### Added

- **Auth-event SSE bridge (SB)** — `GET /private/v1/events/stream` on the private
  router (same `X-Internal-Token` / `PRIVATE_API_SECRET` gate as `jti-status`,
  `include_in_schema=False`). In-process asyncio event hub (`auth_user_service/events/hub.py`)
  with a bounded ring buffer (`EVENT_STREAM_BUFFER_SIZE`, default 256), monotonic
  `<boot-epoch>-<seq>` event ids, `Last-Event-ID` resume (gap → `event: gap` frame),
  per-connection backpressure disconnect, and heartbeat comment frames every
  `EVENT_STREAM_HEARTBEAT_SECONDS` (default 15 s). Hub started/stopped in `lifespan`.
- **Event emission at four sites** (best-effort, never fails the operation):
  `revoke_session_jti`, `revoke_all_user_sessions`, `delete_session_by_jti`, `delete_user`.
  Payloads signed with the existing `EVENT_SIGNING_KEY` via `_signing.serialize`.
- **Three new Prometheus metrics**: `auth_events_published_total{event_type}`,
  `auth_event_stream_connections`, `auth_event_stream_disconnects_total{reason}`.
- **`EVENT_STREAM_*` config knobs**: `EVENT_STREAM_ENABLED` (default `true`),
  `EVENT_STREAM_BUFFER_SIZE`, `EVENT_STREAM_HEARTBEAT_SECONDS`, `EVENT_STREAM_MAX_QUEUE`.
  Added to `auth_user_service/.env` and all six `auth.env.example` files.
- **`auth-sdk-m8 ≥ 1.2.0`** bump in `requirements_base.txt` (SA shipped
  `AuthEventStreamClient`, `SessionRevokedEvent`, and the forbidden-placeholder guard).

### Security

- **Key separation via `SESSION_SECRET`** — the `SessionMiddleware` cookie is now
  signed with a dedicated `SESSION_SECRET`, distinct from `TOKENS_ENCRYPTION_KEY`.
  Rotating the session key no longer invalidates Fernet-encrypted tokens at rest.
  Required at boot.
- **Application-level response hardening wired in (N2), tiered model** —
  `auth_sdk_m8.security.headers.add_security_headers_middleware` (auth-sdk-m8 ≥ 1.2.1,
  pin bumped in `requirements_base.txt`) is attached in `main.py` and now applies headers
  in three tiers on every response (including errors raised before the route handler):
  (1) always-on `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY`; (2) production
  gate (`ENVIRONMENT=production` or `STRICT_PRODUCTION_MODE`) adds `Referrer-Policy` +
  `Permissions-Policy`; (3) **express opt-in** `Strict-Transport-Security` (HSTS) and
  `Content-Security-Policy` (CSP) via `HSTS_ENABLED` / `CONTENT_SECURITY_POLICY_ENABLED`
  (both default `false`) — decoupled from the production gate and **never** emitted on a
  `local` stack even when opted in. No-op overall in local/dev so Swagger/ReDoc keep working.
  Tunable via `SECURITY_HEADERS_ENABLED`, `HSTS_ENABLED`, `HSTS_MAX_AGE`,
  `HSTS_INCLUDE_SUBDOMAINS`, `CONTENT_SECURITY_POLICY_ENABLED`, `CONTENT_SECURITY_POLICY`,
  `REFERRER_POLICY`, `PERMISSIONS_POLICY`.
  **Behaviour change:** HSTS and CSP were previously emitted automatically under the
  production gate; they are now off until explicitly enabled. The opt-in knobs are
  documented (commented, default-off) in the `auth.env.example` / `api.env.example` and
  `fastapi_full` example env templates.

### CI

- **`pip-audit` dependency vulnerability scan** added to the CI workflow.

---

## [0.9.5] — 2026-06-09 · Secure-by-default signing & validation (F1 / F2 / F3)

Adopts the `auth-sdk-m8 ≥ 1.0.0` secure-by-default profile (shipped across 0.9.4–0.9.5).
HS256 and permissive validation remain available as documented opt-outs. See the README
**"Migrating an existing HS256 deployment"** note for the rollout path.

### Security

- **Strict `iss`/`aud` by default (F1)** — `TOKEN_STRICT_VALIDATION=true`. The service
  fails closed at boot unless `TOKEN_ISSUER`/`TOKEN_AUDIENCE` are set, embeds them in
  issued tokens, and requires an exact match on validation. `create_access_token` now
  sets `iat`/`nbf` so self-issued tokens satisfy the strict required-claims set
  (covered end-to-end by `tests/security/test_iss_aud_validation.py`). Opt out with
  `TOKEN_STRICT_VALIDATION=false`.
- **RS256 + JWKS by default (F2)** — `ACCESS_TOKEN_ALGORITHM` defaults to `RS256`; the
  service signs with the mounted private key, embeds a `kid`, and publishes
  `/.well-known/jwks.json` for zero-downtime rotation. RSA keys must be ≥ 2048-bit
  (enforced at boot). `HS256` is opt-in.
- **Secure-by-default event signing (F3)** — fails closed at boot when
  `EVENT_SIGNING_ENABLED=true` (default) and no `EVENT_SIGNING_KEY` is configured. A
  clearly-labelled dev placeholder ships in the example env files and must be replaced
  with a secrets-managed value before staging/production.

### Changed

- `auth-sdk-m8` repointed to `>=1.0.0` (now `>=1.1.0`); `fastapi-m8` repointed to
  `>=1.2.0` in all example requirement files. Every stack's `auth.env.example` and
  `api.env.example` now sets matching `TOKEN_ISSUER`/`TOKEN_AUDIENCE` so each stack —
  auth service and consumer — boots under the strict default.

---

## [0.9.3] — 2026-06-05 · Shell-script permissions + private-route hardening

### Fixed

- All `.sh` scripts stored as `100755` in git (via `git update-index --chmod=+x`,
  independent of host `core.filemode`) — fixes `Permission denied` from bind-mounted
  volumes on WSL2 / Windows / CI runners.
- `verify_private_api_secret` returns **401** for a missing `X-Internal-Token`
  (was 422, leaking endpoint structure); both missing and wrong tokens now return 401.
- Private router excluded from OpenAPI (`include_in_schema=False`); all 6 stacks' Traefik
  `auth-public-router` now excludes `/user/private/`, so private routes return 404 from
  the public internet before reaching the app. A SECURITY CONTRACT comment documents the
  excluded paths.

### Added

- `TestF_MetricsAPI` live tests mirroring `TestF_PrivateAPI` (Traefik 404 + absent from
  OpenAPI for `/user/metrics`); diagnostic `[TRAEFIK MISCONFIGURATION]` messages on the
  F01–F03 private-API failures.

---

## [0.9.2] — 2026-06-05 · Mass-assignment hardening + JTI failure-mode

### Security

- **Explicit field allowlists replace `model_fields` reflection (F4)** — both update
  paths now gate `setattr` on static frozensets: `_SELF_SERVICE_FIELDS =
  {email, full_name, avatar}` (profile) and `_ADMIN_UPDATE_FIELDS =
  {email, full_name, avatar, role, oauth_user_id, hashed_password}` (admin).
  `is_superuser` is absent from both; an injected `is_superuser=True` payload is dropped.
- **Generic OAuth `id_token` error (F7)** — `verify_id_token` returns `"Invalid id_token"`
  instead of leaking the Google-side exception; the original is logged at WARNING.
- **`check_jti_status` honours `ACCESS_REVOCATION_FAILURE_MODE`** (`routes/private.py`) —
  Redis-unavailable returns `active=False` under `fail_closed` (default) and `active=True`
  under `fail_open`, matching `core/deps.py` and `routes/login.py`.

### Removed

- Dead `is_superuser` recheck inside `get_session_by_id` (F9) — the route dependency
  already enforces superuser access, so the body guard could never trigger.

### Changed

- `fastapi-m8` pin bumped to `>=1.1.4`; `SERVE_DOCS_IN_PRODUCTION` documented (commented)
  across all stacks' `auth.env.example`.

---

## [0.9.1] — 2026-06-02 · Supply-chain pinning

- curl pinned to `8.14.1-2+deb13u3` in both Dockerfiles; `trivy-action` pinned to a full
  commit SHA; Trivy scans use `ignore-unfixed: true` to skip OS-level CVEs with no Debian
  fix available yet (all Python packages clean).

---

## [0.9.0] — 2026-06-02 · SecureAndAlign — consumer split, CI hardening, full coverage

### Changed

- **`fastapi_service` example replaced by `fastapi_full` + `fastapi_minimal`** —
  `fastapi_full` (DB session, health checks, auth deps, lifespan teardown) and
  `fastapi_minimal` (three-step bootstrap), both using `fastapi-m8`'s
  `HealthConfig`/`AppLifecycle` API (the old flat-kwargs signature crashed at import).
  All 6 stacks repointed `fastapi_service → fastapi_full` (service name, build context,
  volumes, env mounts, Prometheus targets, Traefik backends). `fastapi-m8` pinned `>=1.1.0`.
- **Auth degradation policy matrix** added to each stack's `api.env`
  (`ACCESS_REVOCATION_FAILURE_MODE` opt-out + `AUTH_STRICT_MODE`) so operators self-select
  their security/availability trade-off.

### Added

- **CI hardening** — Docker base image pinned by digest in both Dockerfiles; `.dockerignore`
  expanded (dev artefacts, tests, VCS excluded); Trivy filesystem scan (PRs) and image scan
  (publish, pre-push); mypy `typecheck` job; **100% branch-coverage gate**
  (`--cov-fail-under=100`). `auth-sdk-m8` bumped to `>=0.6.19`.
- **Route tests** for `profile` (16) and `google_auth` (19) covering all branches,
  including Redis-unavailable, HTTPXError, and callback-URI derivation.

### Security

- **Production Traefik CSP profile** (`production_dynamic_conf.yml`) added to all 6 stacks
  (`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` + HSTS); the dev
  `dynamic_conf.yml` is unchanged so Swagger keeps working.
- **OpenAPI docs gated by `ENVIRONMENT`** — `/docs`, `/redoc`, `/openapi.json` disabled in
  production regardless of `SET_DOCS`; startup `ValueError` if `SET_DOCS=true` +
  `ENVIRONMENT=production`.
- **`TRUSTED_PROXY_COUNT`** setting — `_client_ip()` strips IPv4/IPv6 `:port` suffixes and
  ignores `X-Forwarded-For` entirely when `0`.
- **Email normalisation** (`normalize_email`, auth-sdk-m8 ≥ 0.6.17) on all user-facing
  email fields — prevents mixed-case duplicate accounts.
- **Redis null guard in `is_session_revoked`** — follows `ACCESS_REVOCATION_FAILURE_MODE`
  instead of crashing with `AttributeError` when Redis is unavailable.

### Fixed

- ~80 mypy errors eliminated across the auth service and consumer example; bandit clean
  (0 medium/high); `auth_user_service/.example_env` realigned with the codebase
  (deprecated field names removed, ~15 missing settings added); README Auth & OAuth and
  per-stack OAuth sections completed.

---

## [0.8.4] — 2026-05-28 · Redis isolation — consumer services use HTTP introspection

### Breaking

- **Consumer services no longer connect to auth Redis directly.** `REDIS_*` removed from
  the consumer example and all `api.env` / `api.env.example`; the SDK rejects unknown Redis
  fields for consumer roles (`extra="forbid"`).
- **`INTROSPECTION_URL` + `PRIVATE_API_SECRET` now required** when
  `AUTH_SERVICE_ROLE=consumer` and `TOKEN_MODE=stateful` (`PRIVATE_API_SECRET` must match
  the auth service).

### Added

- **`POST /private/v1/jti-status`** — private inter-service revocation check
  (`{"jti"}` → `{"active"}`), hidden from Swagger, protected by `X-Internal-Token` +
  Docker network isolation, fails-open when Redis is unavailable.
- **`RemoteRevocationClient`** (httpx) in the consumer example; fail-open by default,
  `fail_closed=True` to reject tokens when the auth service is unreachable.

### Changed

- Consumer `get_current_user` is now `async` and calls `RemoteRevocationClient.is_revoked()`
  instead of `AccessTokenBlacklist`; returns 503 in fail-closed mode when introspection is
  unreachable. The consumer no longer depends on Redis to start — only the DB and auth service.

---

## [0.8.3] — 2026-05-23 · Remove avatar upload; clean shared settings; unify secret-key validation

### Breaking

- **`POST /profile/upload_avatar/` removed.** The `avatar` field now accepts only
  `http://` / `https://` URLs (validated at the Pydantic layer). Existing rows holding a
  bare filename must be migrated to a full URL before upgrading.
- **`STATIC_BASE_PATH` / `TEMPLATES_BASE_PATH` removed from `CommonSettings`** and all env
  files — services referencing them must remove the keys.

### Changed

- `SECRET_KEY_REGEX` unified with `PASSWORD_REGEX`: upper + lower + digit + at least one
  non-alphanumeric, no whitespace, min 32 chars. Example generator comments use
  `secrets.token_urlsafe(48)`.

### Removed

- `utils/files.py` (`FilesHelper`), the `ResponseUploadedAvatar` schema, the static mount
  in `main.py`, and the static volumes / empty placeholder dirs across all 6 stacks.

### Fixed

- redis-cli `-a` flag replaced with the `REDISCLI_AUTH` env var across all stacks —
  removes the insecure-password warning on startup and in healthchecks.

---

## [0.8.2] — 2026-05-22 · Stack consolidation (10 → 6), Chrome-extension template, code quality

### Changed

- **Docker Compose examples consolidated 10 → 6**, each serving a distinct audience:
  `quickstart_m8` (HS256 / stateful / MariaDB — start here), `postgres_m8`,
  `rs256_m8` (RS256 / hybrid), `metrics_m8` (Prometheus + Grafana),
  `hardened_m8` (container hardening + Docker Hub image), `vault_m8` (HashiCorp Vault).
  Each stack ships a self-contained README with "choose this when" guidance and a full
  port/config reference.

### Added

- **`examples/addon` — Chrome-extension auth template** — security-reviewed, reusable;
  supports Google OAuth, email/password, and API-key flows against any backend.
- **`GET /google-api/login-url/`** (pure JSON, replaces the Jinja2 HTML login) and
  **`POST /google-api/exchange/`** (one-time `GETDEL` code exchange, PKCE verified with
  `hmac.compare_digest`, rate-limited 10 req/min/IP via `ExchangeRateLimiter`).
- **`GOOGLE_OAUTH_REDIRECT_URI`**, **`OAUTH_ALLOWED_REDIRECT_SCHEMES` / `_PREFIXES`**, and
  **`CORS_ALLOWED_ORIGIN_SCHEMES`** settings + scheme-level CORS regex for Chrome extensions.

### Fixed

- CRLF → LF on startup scripts (root `.gitattributes` enforces `*.sh text eol=lf`);
  `google_auth_callback` cookie `max_age` bug (`timedelta.seconds` →
  `int(total_seconds())`); cyclomatic-complexity refactors across `google_auth_callback`
  and the addon TSX. 100% branch coverage maintained (488 tests).

---

## [0.8.1] — 2026-05-20 · TLS/mkcert, configurable limits, degradation telemetry

### Security

- **Configurable login/refresh rate limits** via `CommonSettings` —
  `LOGIN_RATE_LIMIT_REQUESTS` / `_WINDOW_MINUTES`, `REFRESH_RATE_LIMIT_REQUESTS` /
  `_WINDOW_MINUTES`; startup warns when the effective rate exceeds per-control thresholds.
- **Configurable per-control degradation policy** — `AUTH_STRICT_MODE`,
  `REFRESH_VALIDATION_FAILURE_MODE` / `SESSION_WRITE_FAILURE_MODE` (default `fail_closed`),
  `RATE_LIMIT_FAILURE_MODE` / `ACCESS_REVOCATION_FAILURE_MODE` (default `fail_open`).
- **Refresh key rotation** (`REFRESH_SECRET_KEY_OLD`) — zero-downtime rotation window;
  expired tokens are never retried; a WARNING is logged on each old-key use.
- **`RefreshRateLimiter`** on `/login/refresh-token/` (10 rotations / 5 min per user) —
  closes the session-integrity-denial path (C2).
- **`SameSite=Strict`** refresh cookie; `REFRESH_TOKEN_ALGORITHM` pinned to HS256 at
  startup; `verify_password` exception narrowed to `ValueError`.
- **Redis TLS/mTLS** (`REDIS_SSL`, `REDIS_SSL_CA` / `_CERT` / `_KEY`); redis-py 7.x
  `ssl=False` compatibility fix.
- **New auth metrics** — `auth_revocation_failure_total`, `auth_degraded_decision_total`,
  `auth_redis_circuit_breaker_open`, `auth_degradation_mode_active`,
  `auth_session_integrity_denial_total`; `/health/` gains `circuit_breaker` and
  `degradation_modes`. Degradation contract documented in the README.

### Changed

- **mkcert-based local TLS** with a `cert-init` one-shot container fallback (no host
  prerequisites — bash/openssl/mkcert not required to get HTTPS working).
- `/user/health` and `/user/metrics` restricted to the internal `api` entryPoint
  (localhost-bound port 9000), blocked on the public `websecure` entryPoint.
- CI: Python 3.11–3.14 matrix; standalone bandit job; Docker Hub namespace fix;
  graceful-shutdown `exec` in startup scripts (uvicorn becomes PID 1).

### Added

- `require_redis` live-test marker (auto-skips Redis tests when `/health/` reports
  `redis=unavailable`); `REFRESH_SECRET_KEY_OLD` rotation unit tests.

---

## [0.7.x] — 2026-05-16 → 05-20 · Modular live-test suite + API key rate limiting

### Added

- **Modular live suite** — the monolithic red-team file was split into
  `test_security_universal.py` (13 attack categories) plus algorithm/mode-gated modules
  (`test_asymmetric`, `test_hs256`, `test_stateful`, `test_hybrid`, `test_stateless`),
  auto-skipped via `require_algorithm` / `require_token_mode`; shared fixtures under
  `tests/live/suites/`.
- **API key rate limiting** — fixed-window MINUTE/HOUR/DAY/MONTH (atomic `INCR + EXPIRE`
  pipeline with per-period bucket formats), priority chain (per-key `RateLimit` →
  per-user → `API_KEY_DEFAULT_LIMIT_*`), `X-RateLimit-*` + `Retry-After` headers,
  `get_current_api_key` dependency, write-behind `last_used_at` flush, five
  `auth_api_key_*` metrics + Prometheus alert rules. `RateLimit` model redesigned
  (`api_key_id` FK, `Period.MONTH`, ownership CHECK); `ApiKey.id` migrated to `Uuid`.

### Fixed

- Idempotent superuser seed (guards on any superuser, not the bootstrap email);
  `users.get_user()` by-ID lookup corrected (was querying by email).

---

## [0.6.0] — 2026-05-14 · Atomic rotation, JWKS, observability foundation

### Security

- Atomic refresh-token rotation (Lua) and PKCE `GETDEL` redemption; real client-IP
  attribution behind Traefik; secure-by-default API binding (`API_BIND_IP=127.0.0.1`);
  opt-in HSTS; opt-in `iss`/`aud` enforcement; **JWKS endpoint + `kid` header**;
  `JwksKeyResolver`, `build_access_validator()`, `AccessTokenBlacklist` (SDK);
  timing-attack-safe login (`_DUMMY_HASH`); Redis key-namespace hardening; live red-team
  suite.

### Added

- `GET /health/`; Prometheus metrics (`METRICS_ENABLED`); `RedisRefreshStore` allowlist;
  global 503 handlers for DB/Redis errors; `stateful_m8` / `RS256_m8` / `dev_postgres_m8`
  stacks; security unit suite (~10 modules).

### Breaking

- Existing refresh sessions invalidated on first deploy (users re-login once).
  Requires `auth-sdk-m8 >=0.5.0`.

---

## [0.3.0] — 2026-05-07

- Refresh-token rotation (old JTI revoked as a compromise signal); first FastAPI consumer
  example; first Compose stack (`local_mysql_m8`). Logout reads expiry from `payload.exp`;
  Traefik/Redis pinned with healthchecks. Fixed double-prefixed `/login/test-token/`.

---

## [0.2.0] — 2026-05-06

- Private inter-service API (`/private/`, `X-Internal-Token`); Google OAuth2 + PKCE;
  profile and session endpoints; per-email login rate limiting; dashboard activity
  (superuser); auto-migrations + superuser seed on container start. Split `SECRET_KEY`
  into `ACCESS_SECRET_KEY` / `REFRESH_SECRET_KEY`; `auth-sdk-m8 >=0.2.0`.

---

## [0.1.0] — 2026-05-01

- Initial release: email/password (bcrypt) login, JWT access + HttpOnly refresh-cookie
  pair, Redis session/JTI revocation, MySQL/PostgreSQL via `SELECTED_DB`, RBAC
  (`user` / `admin` / `superuser`), superuser CRUD, multi-stage Docker build (non-root),
  Traefik labels, VS Code remote debugging.
