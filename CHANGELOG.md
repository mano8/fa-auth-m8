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

### Added — Dead-key retention purge + live-key cap correction (Phase 7, `APIKEY-LIFECYCLE-01`)

- New `purge_dead_api_keys()` (`services/api_keys.py`), modelled directly on
  `purge_expired_audit_rows`: a superadmin-gated, horizon-bounded bulk delete
  of dead `ApiKey` rows — revoked (dated by `updated_at`) or expired (dated by
  `expires_at`, with `expires_at IS NULL` never eligible on the expiry basis) —
  checked against a **dedicated** `API_KEY_PURGE_MIN_RETENTION_SECONDS` floor
  (default ≥ 90 days, independent of `AUDIT_PURGE_MIN_RETENTION_SECONDS`) and
  batched under `FOR UPDATE SKIP LOCKED`. Deleting the parent row lets the
  existing `ON DELETE CASCADE` clear its `api_key_audiences` and `RateLimit`
  children in one operation — no audience-only delete path exists. The purge
  accepts no key-id/owner-id/row-scoping parameter (signature-shape locked)
  and writes one `delete` privileged-action audit row (actor, window, rows
  removed) timestamped after the horizon so it survives its own purge (G7-8).
- Exposed as `POST /security/api-keys/purge` — `get_current_active_superuser`-
  gated, `include_in_schema=False`, rate limited by the new
  `ApiKeyPurgeRateLimiter` (`security:api_key_purge:` prefix, already covered
  by every maintained compose example's `~security:*` ACL pattern), floor
  rejection → `400`.
- The per-user creation cap (`routes/api_keys.py::create_api_key`) now
  excludes expired-but-unrevoked keys in addition to revoked ones, so the
  live-key maximum bounds *usable* credentials — an expired row no longer
  forces a manual revoke before a replacement can be issued. The purge, not
  the cap, is what bounds total rows.
- No schema, migration, or introspection request/response shape change:
  `auth-sdk-m8` stays `3.1.0` and `fastapi-m8` stays `4.2.0`.

### Added — API-key audience readback on owner and superadmin key views (Phase 7, `APIKEY-AUD-02`)

- `ApiKeyPublic` (`GET /profile/api-keys/`, `GET /profile/api-keys/{key_id}`,
  `GET /profile/api-keys/verify`) and `ApiKeyAdminPublic`
  (`GET /api-keys/by-user/{user_id}/`) now return the key's persisted
  audience ids as a plain `audiences: list[str]`, read back from the
  normalized `api_key_audiences` relation — a previously set-once, invisible
  binding is now auditable by the owner and by a superadmin (G7-7).
- Implemented as an explicit projection (`ApiKeyPublic.from_key`/
  `ApiKeyAdminPublic.from_key` in `db_models/api_keys.py`), never a bare
  `list[str]` field validated straight off the ORM row — `ApiKey.audiences` is
  a list of `ApiKeyAudience` rows, and a direct `from_attributes` validation
  against `list[str]` would fail. The owner and superadmin list queries add
  `selectinload(ApiKey.audiences)` so a listing stays single-query.
- No schema, migration, or introspection request/response shape change:
  `auth-sdk-m8` stays `3.1.0` and `fastapi-m8` stays `4.2.0`.

### Added — Consumer-side privileged-action audit trail in `examples/fastapi_full` (Phase 7, G7-6)

- New `app_privileged_action_audit` table
  (`examples/fastapi_full/db_models/privileged_action_audit.py`) mirroring the
  issuer's contract for the data the example owns: append-only, no foreign key
  to the actor or the target row (so it outlives both), `row_pk` and
  `target_owner_id` stored as text, `actor_role` stored as a text snapshot.
- New `examples/fastapi_full/app/audit.py` owns the rules:
  `record_privileged_action()` writes exactly one row **in the caller's
  transaction** (flush, never commit), so a category mutation can never commit
  without its audit row; `record_cross_owner_category_action()` is the single
  place deciding that only a mutation of *non-owned* data is privileged; and
  `read_audit_page()` owns the superadmin-all / admin-own read scope.
- The category routes now record every superadmin cross-owner `add`/`edit`/
  `delete`. A delete captures the primary key and the owner **before** the row
  is removed. Mutations of one's own data and refused mutations write nothing.
  The API-key-gated create can never reach a cross-owner mutation (§3.11), so it
  writes no audit row.
- New `GET /security/audit-log` (ADMIN-gated, `include_in_schema=False`,
  read-only) and `POST /security/audit-log/purge` (superadmin-only) in
  `examples/fastapi_full/app/routes/audit.py`. The purge is the table's only
  removal path: horizon-bounded, batched (`FOR UPDATE SKIP LOCKED`),
  floor-enforced (new example settings `AUDIT_PURGE_MIN_RETENTION_SECONDS`,
  default >= 90 days, and `AUDIT_PURGE_BATCH_SIZE`, default 500 — a shorter
  window is rejected with `400`), and it writes its own maintenance row
  timestamped after the horizon. Neither the request body nor the purge
  signature accepts a row identifier, so a targeted delete is not expressible.
- Additive **Expand** Alembic migration creating the table on every maintained
  compose example's `m8_app` chain (`postgres_m8`, `metrics_m8`,
  `quickstart_m8`, `rs256_m8`), installing the `BEFORE UPDATE`/`BEFORE DELETE`
  guard triggers that make the write-once/no-targeted-delete contract
  schema-level on Postgres, MySQL, and MariaDB alike.
- `examples/fastapi_full/core/deps.py` and `app/deps.py` now also surface
  `get_current_active_admin` (from `fastapi-m8` 4.2.0).

### Fixed — Owner comparison in `examples/fastapi_full` category authorization

- `Category.owner_id` is a raw `CHAR(36)`, so a row loaded from the database
  carries its owner as **text** while the authenticated principal's id is a
  `uuid.UUID`. The direct `item.owner_id != current_user.id` comparison was
  therefore true for every owner, denying a non-superadmin WRITER `403` on the
  row it owns. New `app.ownership.as_owner_id()`/`is_owned_by()` normalise both
  sides; the category read/edit/delete authorization and the audit
  cross-owner classification now both use them.

### Security — Ownership preservation in `examples/fastapi_full` (Phase 7, G7-5)

- Owner is now resolved by the server, never set by a request body.
  `CategoryCreate`/`CategoryUpdate` (`examples/fastapi_full/db_models/categories.py`)
  set `extra="forbid"`, so a body carrying `owner_id` is rejected with `422`
  instead of being silently dropped — previously ownership survived an edit
  only because `CategoryUpdate` happened to omit the field.
- New `examples/fastapi_full/app/ownership.py` owns the rules:
  `resolve_create_owner_id()` returns the actor's id only when the actor is the
  intended owner, `category_update_values()` strips every ownership key before
  an edit reaches the row, and `is_canonical_superuser()` centralises the
  dual-evidence predicate. New `db_models.categories.build_category()` copies
  only content fields onto the row, so no payload can reach the ownership
  column.
- A cross-owner create is superadmin-only and requires an explicit
  `target_owner_id` that must resolve to an existing user. It never defaults to
  the actor: a non-superadmin actor gets `403`, an unknown target `404`, and an
  unreachable or unconfigured issuer `503` — no path substitutes the actor's id
  for a target that was refused, unknown, or unverifiable. The API-key-gated
  create always refuses a cross-owner target (§3.11 caps key decisions at
  WRITER).
- New `examples/fastapi_full/core/user_directory.py` resolves the target owner
  over the issuer's owned HTTP contract
  (`GET {AUTH_PREFIX}/users/get/{user_id}/`, derived from `INTROSPECTION_URL`)
  with the caller's own bearer token — the consumer never reads the auth
  service's user table. Fail-closed on every non-definitive outcome; errors
  carry a bounded reason code only, never the token or the response body.
- New bundled-example unit suite (`examples/fastapi_full/tests/`) with its own
  `pytest.ini`, gated by the new `example-tests` CI job and locked by
  `tests/test_ci_policy.py`.

### Added — Superadmin audit retention-purge maintenance action (Phase 7, 3.5.1)

- `POST /security/audit-log/purge` (`auth_user_service/routes/security.py`):
  the append-only `privileged_action_audit` table's sole removal path — a
  `get_current_active_superuser`-gated bulk delete of rows older than a chosen
  retention window (`1w`/`1m`/`3m`/`6m`/`1y`), enforcing a minimum-retention
  floor (new settings `AUDIT_PURGE_MIN_RETENTION_SECONDS`, default >= 90 days,
  and `AUDIT_PURGE_BATCH_SIZE`, default 500). A window shorter than the floor
  is rejected with `400`; lowering the floor is an explicit operator config
  change, never a per-call parameter.
- `auth_user_service/services/audit.py::purge_expired_audit_rows`: the
  batched (`FOR UPDATE SKIP LOCKED`) delete implementation, mirroring the
  outbox worker's batching so a large purge never holds one long-lived lock.
  There is deliberately no row-id parameter — the horizon is the only
  selector, so this can never become a targeted single-row delete. The purge
  always writes its own `delete` maintenance audit row (actor, window, rows
  removed) via the existing `record_privileged_action`, timestamped after the
  horizon it was computed from, so it always survives the purge that wrote it
  (mirrors the tombstone retention-horizon + guarded-cleanup pattern, 3.5.1).
- New `AuditPurgeRateLimiter` (`auth_user_service/core/client.py`), keyed by
  caller user id under the existing `security:` ACL prefix (no ACL change
  needed); route excluded from the OpenAPI schema like its `audit-log` sibling.
- `auth_user_service/route_inventory.json` gains the new route entry
  (`admin` exposure); `README.md` documents the audit trail and purge
  contract in a new _Privileged-action audit trail and retention purge_
  subsection.

### Added — Consume the SDK canonical fixture matrix (Phase 5, FIXTURE-01)

- Raise the `auth-sdk-m8` floor in `auth_user_service/requirements_base.txt`
  to `>=3.1.0,<4.0.0` to consume the expanded, checksummed
  `authorization_matrix.json` (schema version `"2"`) from
  `auth_sdk_m8.testing.load_authorization_fixture_matrix()`.
- `tests/routes/test_private_fixture_matrix_contract.py` drives the issuer's
  own `JtiStatusRequest`/`ApiKeyIntrospectionRequest` schemas and the
  `check_jti_status`/`introspect_api_key` route handlers directly from the
  canonical fixture data (JTI-status v1/v2, API-key introspection shapes,
  local/remote principal equivalence, and the audience/capability-policy
  matrix) instead of locally invented expectations, so an SDK-side contract
  drift fails this suite too.
- Raise the bundled `examples/fastapi_minimal/requirements.txt` and
  `examples/fastapi_full/requirements_base.txt` `fastapi-m8` floor to
  `>=4.1.0,<5.0.0`, matching the coordinated `auth-sdk-m8 3.1.0` /
  `fastapi-m8 4.1.0` fixture-consumption bump so both maintained examples
  install the SDK/fastapi-m8 pair that ships the expanded fixture matrix.

**Known gap:** `auth_user_service/requirements_prod.lock` still pins
`auth-sdk-m8==3.0.0` — regenerating it with `pip-compile --generate-hashes`
requires `auth-sdk-m8 3.1.0` to already be resolvable from the configured
package index, which is a Phase 6 (coordinated release) precondition, not
this Phase 5 test-consumption change. Regenerate the lock as part of the
Phase 6 publish sequence. The same applies to the two bumped example
`requirements*.txt` floors: `pip install` against them (including this
repository's own CI, which installs `examples/fastapi_full/requirements_base.txt`)
only resolves once `auth-sdk-m8 3.1.0` and `fastapi-m8 4.1.0` are actually
published to the configured package index.

---

## [2.0.0] - 2026-07-22

### Security

- **Every revocation path is database-authoritative (`REV-PATH-01`, 3.5.4;
  audit finding 8).** `SessionController.revoke_session_jti` was Redis-only — a
  blacklist write plus a best-effort event, with no authoritative DB write — so
  the revocation was silently lost whenever Redis was down, and any future
  caller inherited the defect. It now takes a mandatory `session` and deletes
  the authoritative `ClientSession` row **before** touching Redis, committing
  the authoritative state first; the blacklist entry and the `session-revoked`
  event are accelerators only. The logout path passes its request session
  through (`routes/login.py::_revoke_access_jti`) and keeps its fail-closed
  `SESSION_WRITE_FAILURE_MODE` posture. The administrative revocation routes
  (`DELETE /sessions/delete/{session_id}/`, `DELETE
  /sessions/delete-by-user/{user_id}/`) were the mirror-image gap — DB-
  authoritative but with **no** accelerator, so a consumer's positive cache
  entry outlived the database decision until its TTL; they now route through
  `SessionController.revoke_session_record` /
  `revoke_all_user_sessions`, which blacklist the captured JTIs, drop the
  matching refresh-allowlist entries, and emit a per-JTI (single) or user-wide
  (bulk) event. `apply_post_commit_revocation` gained the `user_wide` switch
  that narrows eviction to the captured targets for the single-session case.
  All ten paths enumerated in 3.5.4 are audited and documented in the new
  README section _Database-authoritative revocation_.
- **Per-path revocation-persistence tests** (`tests/services/test_revocation_paths.py`,
  23 tests). Every enumerated path — logout, individual revocation,
  administrative single/bulk revocation, refresh rotation, refresh-reuse
  response, role change, deactivation/reactivation, deletion, security repair,
  and the global legacy-session revocation — asserts both that the
  authoritative session state is persisted in the same transaction/operation
  and that a fresh subject-bound **v2** `/private/v1/jti-status` request
  **with Redis down** still denies from database state alone. Includes an
  active baseline (so denial is caused by revocation, not by setup), a proof
  that the authoritative delete survives a failing blacklist write, and a
  signature regression lock asserting no revocation entry point can be called
  without an authoritative DB session.

### Fixed

- **Coverage gate now measures the authorization-bearing route code (3A-2).**
  `.coveragerc` no longer blanket-omits `auth_user_service/routes/*` and
  `auth_user_service/scripts/*`; `pytest --cov-fail-under=100` previously
  asserted nothing about them. Added the route-level error-mapping tests for
  `routes/users.py::update_current_user`/`delete_user` — the operator-visible
  `403` (`SelfPromotionError`), `409 last_superuser_required`
  (`LastSuperuserError`), `404`, email-`409`, and generic-500 branches — plus
  coverage for the pre-existing `read_users`/`create_new_user_with_password`/
  `register_user`/`read_user_by_id` routes and two edge cases in the
  `check_no_direct_superuser_auth` AST guard
  (`tests/security/test_no_direct_superuser_auth.py`). `routes/login.py`,
  `routes/sessions.py`, and `routes/api_keys.py` stay in the omit list as
  pre-existing surfaces exercised only by `tests/live` (ignored by the CI unit
  gate); a handful of other pre-existing, live-tested-only code paths
  (`routes/private.py::event_stream`, the two `routes/dashboard.py` handlers,
  and one defensive branch in `routes/oauth_login.py::_is_safe_http_redirect`)
  are marked `# pragma: no cover` in place with a recorded justification
  rather than reintroducing a blanket omit. Full suite: 1296 passed, 100%
  statement/branch coverage under the narrowed scope; ruff format/check, mypy,
  bandit, `check_no_direct_superuser_auth`, and pip-audit all clean.

### Added

- **Bundled examples raised to `fastapi-m8 >=4.0.0,<5.0.0`.** `examples/fastapi_minimal/requirements.txt`
  now floors on the 4.x line (`fastapi_full` already did); `fastapi_minimal/routes.py` demonstrates
  all four JWT dependency levels (`get_current_user`/`get_current_active_writer`/
  `get_current_active_admin`/`get_current_active_superuser`) and `fastapi_full` gains one
  API-key-gated writer route (`POST /category/api-key/add/`,
  `app/routes/api_key_category.py`) wired through the remote API-key principal
  dependency (`get_current_api_key_writer`, §3.12) — present only when
  `API_KEY_INTROSPECTION_ENABLED=true` is set. Neither example re-implements a
  role or `is_superuser` check; every guard is the shared dependency built by
  the single `build_auth_deps` call.
- **Read-only mismatch/last-superuser preflight (§4.1).** New
  `auth_user_service/services/security_preflight.py`
  (`SecurityPreflightController.run`) scans for existing
  `is_superuser`/`role` mismatches ahead of the Expand → repair → Enforce
  migration sequence: counts and ids where `is_superuser=true` with a
  non-SUPERADMIN role, counts and ids where `role=SUPERADMIN` with
  `is_superuser=false`, the active canonical-superuser count, and which
  mismatched ids hold an active session — never email, token, JTI, or session
  payloads. Every query selects individual scalar columns only (never
  `select(User)` or `User.model_validate`), so a row the preflight exists to
  find can never itself raise while being found. A new read-only CLI,
  `python -m auth_user_service.scripts.security_preflight`, exits `1` when any
  mismatch is found (per 4.4 step 1, run before the coordinated release) and
  `0` otherwise; it writes nothing and never auto-promotes/demotes.
  `SecurityRepairController.repair_user` is the explicit audited repair
  command that resolves a reported mismatch: the operator supplies the
  intended role explicitly (never inferred), and on a real change it
  propagates exactly like the runtime role-change transaction — bumps
  `auth_generation`, revokes the owner's sessions, and enqueues the same
  durable outbox effects (blacklist + user-wide v2 event) — with no separate
  API-key revocation step, since key authorization is evaluated live against
  the owner's current row (§3.11). It reads and writes raw columns only
  (never a `User` write), takes only the target row's own lock (a row
  eligible for repair is never counted as an active canonical superuser
  today, so repair can only add to that set, never remove from it — the
  last-superuser invariant cannot be violated here), is idempotent (repeating
  the same repair is a no-op), and rejects (`NotMismatchedError`) a retarget
  of an already-consistent row to a different role — that is a plain role
  change and goes through `services.role_admin` instead. The CLI is
  `python -m auth_user_service.scripts.security_repair --user-id <uuid>
  --intended-role <role> --actor <who> --reason <why>`.
- **Global legacy-session revocation (§4.1 step 5, §4.2).** New
  `auth_user_service/services/legacy_session_revocation.py`
  (`GlobalLegacySessionRevocationController.revoke_legacy_sessions`) deletes
  every `ClientSession` row that still carries no `auth_generation` — every
  access and refresh session that predates the Expand migration — and never
  backfills a generation onto them (backfilling could bless an old canonical
  token carrying a stale role). This is what allows
  `ClientSession.auth_generation` to become `NOT NULL` in Enforce. It runs
  once, inside the write-quiescent maintenance window, after Expand and the
  preflight/repair pass and before Enforce; deletion alone is authoritative
  for the stateful validation path, and it is idempotent (a repeat run finds
  zero remaining legacy rows). The audited CLI is
  `python -m auth_user_service.scripts.legacy_session_revocation --confirm
  REVOKE-ALL-LEGACY-SESSIONS --actor <who> --reason <why>`; it requires the
  literal confirmation token because this is a one-time, all-users forced
  global logout — every user must sign in again after cutover — for stateful
  deployments and for refresh flows in every mode. Hybrid/stateless access
  tokens that are still wire-valid keep working only until their own natural
  expiry (the documented bounded window, §3.6), because no server-side
  session backs them.
- **API-key `access_mode` and normalized audience bindings (§3.11–§3.12,
  Expand).** `ApiKey` gains an immutable `access_mode` column (`read_only` /
  `read_write`, `NOT NULL`, server default `READ_ONLY` so every existing key
  migrates to the most restrictive cap — `APIKEY-MODE-01`; it is an
  operation-category cap, never a role). Audiences persist in a new normalized
  `api_key_audiences` relation (composite PK, `ON DELETE CASCADE`) rather than a
  nullable plural column or native array, because the supported engines include
  MySQL/MariaDB (`APIKEY-AUD-01`). `POST /profile/api-keys/` accepts the two
  additive, explicit-only creation fields `access_mode` and `audiences` (both
  fixed at issuance); an audience must be an enabled consumer explicitly granted
  the `api-key-introspection` scope and is capped by the new
  `API_KEY_MAX_AUDIENCES` setting (`409` on an invalid/ineligible audience). A
  key with **no** audience rows is issuer-local only — remote introspection
  answers `active: false`, the fail-closed cutover that stops any legacy key
  silently becoming a cross-service credential. Legacy keys are migrated by a new
  audited operator command,
  `python -m auth_user_service.scripts.bind_api_key_audiences` (audiences only,
  idempotent, refuses to change an already-bound immutable set), and the private
  `/private/v1/api-keys/introspect` endpoint now evaluates the real relation for
  the owner-role ∩ `access_mode` ∩ audience narrowing rule.
- **Per-user authorization generation (`auth_generation`).** A monotonic,
  issuer-owned `BIGINT` revocation watermark now lands on `User` (`NOT NULL`,
  default `1`) and `ClientSession` (nullable during Expand; a `NULL`/absent stamp
  is treated as revoked). Sessions are stamped with the owner's current generation
  at issuance, a real role change increments it transactionally, and a hard delete
  first writes a durable `auth_tombstone` row (no FK cascade, idempotent
  max-generation upsert) so introspection can treat every token minted for the
  deleted subject as revoked. New `auth_user_service/services/generation.py` owns
  the framework-neutral primitives (`GENERATION_START`, `GENERATION_MAX`,
  fail-closed no-wraparound `next_generation`, the `is_session_generation_stale`
  predicate, the retention horizon) and the DB-facing `GenerationController`
  (generation bump, tombstone upsert/lookup, the stale-generation check used by
  the introspection path, and horizon-guarded tombstone cleanup). The route-owned
  role-change transaction/lock, the transactional outbox, and the v2
  `/private/v1/jti-status` decision endpoint compose these primitives in later
  changes; the token wire shape is unchanged (3.5.1).
- **Subject-bound v2 `/private/v1/jti-status` introspection.** The private
  endpoint now answers a subject-bound v2 request
  (`{jti, expected_user_id, schema_version: "2"}`) with the database-authoritative
  decision (`GenerationController.decide_jti_status`, 3.5.2): in `stateful` mode it
  evaluates, in order, the deletion tombstone, a missing/revoked session, a subject
  mismatch, a missing/inactive/claim-inconsistent owner, a stale session
  generation, and finally the Redis blacklist. Only a current session owned by the
  asserted subject behind a canonical, active, current-generation owner is
  `{active: true, user_id, auth_generation, schema_version}`; **every** inactive
  cause returns one generic `{active: false, schema_version}` (no account-state or
  JTI-validity enumeration oracle). An unreachable authoritative database returns
  `503` — the generation decision never falls open, so
  `ACCESS_REVOCATION_FAILURE_MODE=fail_open` is not honoured for it; a Redis outage
  falls back to the DB result. Hybrid/stateless keep the expiry-bounded contract
  (3.6). A legacy `{jti}`-only request is unchanged and still receives the bare v1
  `{active}` response, so consumers upgrade at their own pace (`JTI-DECISION-01`).
- **Route-owned superuser-set transaction, portable lock, and centralized
  last-superuser predicate.** New `auth_user_service/services/role_admin.py` owns
  one transaction that serializes every mutation which can add to or remove from
  the active canonical-superuser set — role demotion, deactivation, and hard
  deletion, including the self- variants. It acquires a portable singleton
  policy-row lock (`SELECT ... FOR UPDATE` on the new seeded
  `<prefix>_security_policy` row — the cross-engine replacement for
  `pg_advisory_xact_lock`, since MySQL/MariaDB lack advisory locks), locks the
  target user row in a fixed order (policy → user → session/API-key rows), counts
  active canonical superusers under the lock, enforces the invariant
  (`409 last_superuser_required`), applies the mutation with the server-derived
  flag and the `auth_generation` increment, revokes the user's sessions in the
  same transaction, and bumps the policy revision — committing once (3.5.3
  `REV-LOCK-01`). The centralized predicate
  `is_active_canonical_superuser(user)` (`role == SUPERADMIN and is_superuser and
  is_active`, via the shared SDK dual-evidence check) is the single definition
  every guard routes through. `UserController` and `SessionController` gain
  transaction-neutral internals (`apply_user_update`,
  `capture_and_delete_user_sessions`, `apply_post_commit_revocation`) so no nested
  helper commits during a role transition; the existing `update_user` /
  `revoke_all_user_sessions` wrappers compose them unchanged. The durable
  transactional outbox that replaces the best-effort post-commit Redis/event push
  is a later change.
- **Admin activation control on `UserUpdate` (`is_active`).** The admin update
  schema gains an optional `is_active` flag. Applied only by the route-owned
  transaction, an activation transition bumps the generation and revokes sessions
  in both directions.
- **Transactional revocation outbox for role changes.** Role-change revocation
  side effects are now recorded as durable outbox rows committed **atomically**
  with the DB revocation instead of the best-effort post-commit Redis/event push
  (3.5.2 `REV-OUTBOX-01`/`REV-EVENT-01`). New `<prefix>_revocation_outbox` table
  (`auth_user_service/db_models/outbox.py`): separate effect rows each with their
  own `status` (`pending`/`leased`/`completed`/`dead`), unique on
  `(user_id, auth_generation, effect_type, target_digest)` so duplicate
  enqueue/drain is harmless — **one `blacklist` row per captured `(jti, expires_at)`
  target** (payload-carried, so no expiry is lost to aggregation) plus **one
  user-wide `publish` row** carrying the durable **v2** `session-revoked` event
  (`version="v2"`, `auth_generation`, deterministic `event_id`). New
  `auth_user_service/services/outbox.py` adds `OutboxController.enqueue_role_change_effects`
  (transaction-neutral enqueue) and `OutboxWorker`, an at-least-once drain worker:
  claims a batch with `FOR UPDATE SKIP LOCKED` + a time-bounded lease
  (an expired lease is the only recovery path for a crashed worker), applies the
  Redis blacklist with a TTL **derived from the captured per-target token expiry**
  and the durable event publication, retries with bounded exponential backoff,
  dead-letters (`status='dead'`) on exhaustion, and reaps completed rows after a
  retention window. A background drain loop is wired into the app lifespan
  (`OUTBOX_WORKER_ENABLED`, `OUTBOX_*` settings). The DB delete remains the
  authoritative revocation (3.5.4), so a disabled/lagging worker only slows
  propagation.
- **Role-change response contract (`200` + `revocation_enqueued`).** The
  `PATCH {API_PREFIX}/users/update/{id}/` response is now `UserAuthorizationUpdate`
  — the public user plus `auth_generation` and `revocation_enqueued` — returned
  once the single transaction commits. It never implies downstream propagation has
  completed and never returns a post-commit `503`/`202` (3.5.2). A pure profile
  update reports `revocation_enqueued: false`.
- **Revocation-propagation metrics.** New `auth_user_service/services/outbox_metrics.py`
  registers `<prefix>_revocation_outbox_{enqueued,completed,retried,dead}_total`
  (labelled by `effect_type`) and the `<prefix>_revocation_outbox_propagation_seconds`
  histogram (commit→delivery latency) on the shared `/metrics` registry. JTIs are
  never used as label values.
- **Private API-key introspection endpoint (`POST /private/v1/api-keys/introspect`,
  §3.12).** The distributed half of the API-key authorization rule: a consumer
  service that does not share the issuer database resolves a **user API key** to
  the same canonical live owner principal `fa-auth-m8` uses locally. The route
  (`include_in_schema=False`) is gated by a dedicated `api-key-introspection`
  `ConsumerScope` — kept distinct from `introspection` so a JTI-status consumer is
  not implicitly granted key introspection. It follows the normative §3.12
  processing order: authenticate the internal consumer → verify the scope →
  consume a per-consumer anti-abuse allowance → resolve the key (hash lookup,
  revocation, expiry) → resolve the owner live → check activity/canonical
  consistency → derive the audience from the **authenticated consumer's registry
  identity** (never the request body) → verify the key carries it → compute the
  constrained principal → consume the key's functional quota → queue the
  `last_used_at` write-behind → return. The raw key travels as a redacted
  `SecretStr` body (a client-generated hash is never accepted; the key never
  appears in the URL, logs, traces, or error messages). Status matrix: `401`
  invalid/missing internal credential, `403` credential lacking the scope, one
  generic `200 {active: false}` for **every** unusable cause (unknown/revoked/
  expired key, missing/inactive/claim-inconsistent owner, or an audience the key
  does not carry — no account-state oracle), `200 {active: true, …}` with the
  minimized principal (owner role/superuser evidence ∩ the key's immutable access
  mode, plus `audience_id` and `key_expires_at`; never `is_active`, key hash/id,
  or email), `429`+`Retry-After` on functional-quota exhaustion with local-auth
  parity, and `503` on DB-unavailable, an unknown requested schema version, or
  strict-Redis quota unavailability (never fail-open). Because the normalized
  `api_key_audiences` relation lands in a later Expand change, **no key yet
  carries an audience**, so remote introspection currently answers `active: false`
  for every consumer — the documented fail-closed cutover in which no existing key
  silently becomes a cross-service credential. Supporting refactor:
  `authenticate_private_consumer` now returns the authenticated consumer id (the
  audience source; `require_private_scope` is a thin wrapper over it), and
  `resolve_api_key_owner_principal` is the shared non-raising owner-principal
  resolver used by both the local dependency (which maps the miss to the generic
  `401`) and this endpoint (which maps it to `active: false`), so the two paths
  cannot drift. New setting `API_KEY_INTROSPECTION_ANTIABUSE_PER_MINUTE`
  (default `600`) bounds the per-consumer anti-abuse ceiling, observed with the
  registry-bounded consumer id label only.

### Changed

- **Issuer SDK floor raised to `auth-sdk-m8 >=3.0.0,<4.0.0`** (was
  `>=2.1.1,<3.0.0`) in `auth_user_service/requirements_base.txt`, with the matching
  `requirements_prod.lock` pin (`auth-sdk-m8==3.0.0`). The `3.0.0` major ships the
  canonical role/`is_superuser` invariant and the shared, framework-neutral
  authorization policy (`has_superuser_privileges`, `validate_privilege_claims`).
- **CT-1 CONTRACT_VERSION 0.9→1.0.** `auth_user_service/core/service_meta.py` and the
  two example consumers (`fastapi_full`, `fastapi_minimal`) now declare
  `CONTRACT_VERSION = "1.0"`. The CONTRACT_RANGE (`>=1.0.0 <2.0.0`) and the service
  version are unchanged. Aligns the declared contract to the 1.x stable line that
  retired the legacy single-`PRIVATE_API_SECRET` private-API gate.
- **Live-test harness aligned to security-tests-m8 0.3.0.** All per-stack
  `test.env(.example)` files and `shared_live_tests` now carry `LIVE_TEST_INTERNAL_AUTH_BASE`
  (F06 fix — targets the internal service-to-service entrypoint for per-consumer
  legacy-shape probes on hardened stacks that block `/private` at the public edge) and
  document `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` (9.3 / Design-B opt-in for deep
  `/health` detail; ungated body is always the constant liveness response).
- **Canonical `superuser` test fixture.** `tests/conftest.py`'s `superuser`
  fixture now carries `role=SUPERADMIN` (was `role=USER`) so it satisfies the new
  role/flag invariant.

### Security

- **Canonical superuser authorization — no flag-only privilege checks.**
  `get_current_active_superuser` and every direct privileged-flag check
  (`routes/users.py`, `routes/profile.py`, `services/dashboard.py`) now authorize
  through the shared SDK `has_superuser_privileges(role, is_superuser)`
  dual-evidence predicate instead of the bare `is_superuser` flag. An
  `is_superuser=true` flag paired with a non-`SUPERADMIN` role (or the inverse) can
  no longer grant superuser access.
- **Persisted privilege claims validated before token signing.**
  `AuthController.create_auth_tokens` — the single login/refresh signing chokepoint —
  validates the persisted `role`/`is_superuser` pair via the SDK before issuing a
  token. An inconsistent row fails closed (HTTP 500) and emits a bounded,
  secret-free security event
  (`event=token.sign.blocked reason=inconsistent_privilege_claims`); an inconsistent
  access token is never signed.
- **`is_superuser <=> role == SUPERADMIN` enforced at the model, service, and
  database layers.** `auth_user_service/db_models/users.py` adds the named DB check
  constraint `ck_user_superuser_role_consistency`
  (`is_superuser = (role = 'SUPERADMIN')`, compared against the verified persisted
  enum member label `'SUPERADMIN'`, NULL-safe via the existing `NOT NULL` columns)
  plus a model invariant that fires on `User.model_validate`. `is_superuser` is now
  **derived evidence** of the authorized role, never a client-submitted switch:
  `UserController.create_user`/`update_user` derive the flag server-side from the
  role (`SUPERADMIN → true`, all others → `false`) in one place, ignoring any
  client-supplied value, so a caller can never submit an inconsistent or
  self-elevating pair. The DB constraint stays authoritative for direct SQL and
  race paths.
- **CI AST guard bans direct `is_superuser` authorization checks.**
  `auth_user_service/scripts/check_no_direct_superuser_auth.py` (wired into the CI
  `lint` job) fails the build on any boolean authorization decision that reads
  `<user>.is_superuser` directly; the only sanctioned path is the SDK dual-evidence
  predicate `has_superuser_privileges(role, is_superuser)`. Serialization and ORM
  column use are unaffected.
- **Last-superuser protection on demotion, deactivation, and deletion.** A role
  change, deactivation, or deletion that would remove the last active canonical
  superuser is now rejected with `409 last_superuser_required`, evaluated under
  the portable superuser-set lock so a concurrent set mutation cannot slip past
  the check (3.5.3).
- **No self-promotion.** An actor may never raise their own role via the admin
  update route; the attempt returns `403` (role-administration matrix, 3.10).
  Self-demotion and self-deletion remain allowed, subject only to the
  last-superuser rule — the previous blanket `403` "super users may not delete
  themselves" guard on `DELETE /users/delete/{id}/` is **replaced** by that rule.
- **Deactivation revokes the owner's API keys.** Setting `is_active=false` now
  marks every one of the user's API keys `revoked=true` in the same transaction,
  and reactivation never clears `revoked` — an incident-response deactivation can
  no longer silently re-arm possibly compromised credentials when the account is
  re-enabled (3.11). Every activation transition (both directions) also bumps the
  authorization generation and revokes the user's sessions.

---

## [1.1.0] — 2026-07-02 · Security-remediation hardening + toolchain/env alignment

> **Consolidates the never-tagged `1.0.1` fix.** The `1.0.1` `db_data/` reset fix
> (below, under _Fixed_) was drafted but never published as a git tag; it ships as
> part of `1.1.0`. The package `__version__` and the `fastapi_full` /
> `fastapi_minimal` example consumers are aligned to `1.1.0`; the issuer `/meta`
> `CONTRACT_RANGE` stays `>=1.0.0 <2.0.0` (no contract break).
>
> **Toolchain floors raised.** The example consumers move to
> `fastapi-m8 >= 3.3.0` (was `>= 3.2.0`) and the issuer to `auth-sdk-m8 >= 2.1.1`
> (was `>= 2.1.0`) in `auth_user_service/requirements_base.txt`. `fastapi-m8 3.3.0`
> itself requires `auth-sdk-m8 >= 2.1.1`, so the whole chain converges on one SDK
> version in a shared virtualenv. The pinned `requirements_prod.lock` already
> resolves `auth-sdk-m8==2.1.1`, so the floor bump needs no lock regeneration.

### Security

- **API-key rate limiting now fails closed in production/strict (11.3).** When
  Redis is unavailable, valid API keys were previously admitted with no
  rate-limit ceiling unless `API_KEY_STRICT_RATE_LIMIT=true` was set separately.
  Strict behaviour is now **inherited** from any production/strict posture
  (`ENVIRONMENT=production`, `STRICT_PRODUCTION_MODE=true`, or
  `AUTH_STRICT_MODE=true`) via the new
  `Settings.effective_api_key_strict_rate_limit` — such deployments return `503`
  instead. Non-production, non-strict development still fails open but now logs
  the admission as unsafe. Both paths emit a `degraded_decision_total`
  (`control="api_key_rate_limit"`) metric sample; logs carry only the opaque key
  id, never the raw key. Hardened production env example sets
  `API_KEY_STRICT_RATE_LIMIT=true` explicitly for auditability.
- **Release images now install a hash-locked dependency set (11.8).** Non-development
  Docker builds no longer resolve the loose lower-bound ranges in
  `requirements_base.txt` / `requirements_prod.txt` at build time. They install
  from the new fully pinned, `sha256`-hashed `auth_user_service/requirements_prod.lock`
  via `pip install --require-hashes`, so rebuilding the same source cannot silently
  pull a different dependency graph and the published SBOM matches what shipped. All
  packages (including the internal `auth-sdk-m8`) resolve from public PyPI only. The
  development build path is unchanged. Regeneration and audit steps are documented in
  the README; the lock, the Dockerfile `--require-hashes` install, and the
  SBOM-reflects-locked-env invariant are enforced by
  `tests/security/test_dependency_lock.py`.

### Changed

- **Example-consumer dependency floors raised** to `fastapi-m8 >= 3.3.0,<4.0.0`
  in `examples/fastapi_full/requirements_base.txt` and
  `examples/fastapi_minimal/requirements.txt`, with the issuer moved to
  `auth-sdk-m8 >= 2.1.1,<3.0.0`. The DOCKERHUB integration snippet is bumped to
  match.
- **Env examples aligned and documented across the service, `fastapi_full`, and
  every `examples/docker_compose/*` stack.** `examples/fastapi_full/.example_env`
  now documents the keys its runnable `.env` already used (`SECRET_KEY`,
  `GFORM_PREFIX`, `PROMPTS_PREFIX`, `TOKEN_STRICT_VALIDATION`,
  `EVENT_SIGNING_ENABLED`/`EVENT_SIGNING_KEY`, `REVOCATION_CACHE_TTL_SECONDS`);
  the issuer `.example_env` documents the opt-in `HEALTH_DETAIL_CREDENTIAL` gate;
  and every stack's live-test config gained an explicit `LIVE_TEST_AUTH_HEALTH_URL`.

### Fixed

- **Route-inventory test is robust to FastAPI ≥ 0.137 lazy router inclusion.**
  `include_router` no longer flattens sub-routes into `app.routes` (it inserts an
  opaque `_IncludedRouter`), which made `tests/security/test_route_inventory.py`
  report every inventory entry as stale under a freshly resolved FastAPI. The
  test now descends through both the flattened (≤ 0.136) and nested (≥ 0.137)
  shapes to reconstruct the full route surface. The two `api_key.rate_limit_*`
  degraded-mode log lines carry an explicit `# nosec B106` (the `ref` field is
  the opaque key id, not a secret), matching the existing logger suppressions.
- **rs256 stack could not run the per-consumer private-API live checks.**
  `rs256_m8/auth.env` was missing `PRIVATE_API_CONSUMERS` (and `api.env` its
  `INTERNAL_CLIENT_ID`), so the `example-api` consumer the security suite
  authenticates as was never registered — every `/private/*` call failed closed.
  Both are now set, matching the other stacks and the stack's own `*.env.example`.
- **Per-stack live-test root variable was a copy-paste of `HARDENED_M8_STACK_ROOT`.**
  The `metrics`/`postgres`/`quickstart`/`rs256`/`vault_dev` `test.env` and
  `test.env.example` files referenced the hardened stack's variable name; each now
  uses its own `<STACK>_M8_STACK_ROOT` (the runner keys off
  `LIVE_TEST_DEPLOYMENT_ROOT`/`LIVE_TEST_REPO_ROOT`, so behaviour is unchanged —
  the fix is documentation correctness).
- **`examples/docker_compose/shared/scripts/init-common.sh` — `--reset-db` now
  removes a container-owned `db_data/`** (originally staged for the never-tagged
  `1.0.1`). PostgreSQL creates `db_data/` as its own container uid (e.g. `70`,
  mode `0700`), so a host-side `rm -rf db_data/` fails with "Permission denied" on
  WSL2/Linux bind mounts, leaving stale data that silently blocks re-init. The
  reset now tries the host `rm` first and falls back to a throwaway root `alpine`
  container (`docker run --rm -v "$(pwd):/work" alpine rm -rf /work/db_data`) to
  delete the container-owned directory, erroring out with a `sudo` hint only if
  both fail. Backported from `media-service-m8`'s stack tooling; the two repos'
  `init-common.sh` are now byte-identical.

---

## [1.0.0] — 2026-06-25 · First stable line — per-consumer private-API auth (legacy `PRIVATE_API_SECRET` gate retired), short-TTL service tokens, dual-key token encryption

> **First `1.x` release.** `1.0.0` is the first stable line of `fa-auth-m8`,
> reclaiming the version after the security-remediation `0.9.x` baseline. It
> supersedes the abandoned early `1.x`/`2.x` tags, which were never real
> `fa-auth-m8` releases. The package `__version__`, the issuer `/meta`
> `CONTRACT_RANGE` (now `>=1.0.0 <2.0.0`), and the `fastapi_full` / `fastapi_minimal`
> example consumers are all aligned to `1.0.0`.
>
> **Requires `auth-sdk-m8 >= 2.1.0` (and `< 3.0.0`)** — pin bumped in
> `auth_user_service/requirements_base.txt`. This consumes the SDK's 9.1
> verification primitives (`ConsumerCredentialRegistry`, `make_consumer_authorizer`)
> and keeps the issuer on the **same SDK version the example consumers resolve**:
> their `fastapi-m8 >= 3.2.0` floor requires `auth-sdk-m8 >= 2.1.0`, so a shared
> virtualenv installs one consistent SDK across issuer and consumers. The `2.1.0`
> floor also carries the `pydantic-settings >= 2.14.2` security patch
> (symlink-traversal hardening in the nested-secrets source). 2.0.0 already
> **single-mounts** the liveness `/ping` route (served only at
> `{API_PREFIX}/ping` and advertised in the schema; the root `/ping` is no longer
> mounted) — a breaking change vs the 1.5.0 dual-mount; the `/ping` test is
> updated accordingly.

### Removed — BREAKING

- **Legacy single-`PRIVATE_API_SECRET` private-API gate retired** (plan item —
  `PRIVATE_API_SECRET` retirement, fa-auth-m8 side). The `/private/*` routes no
  longer accept a single shared `X-Internal-Token` matching `PRIVATE_API_SECRET`.
  Per-consumer credentials (`X-Internal-Client` + `X-Internal-Token`, authorized
  against `PRIVATE_API_CONSUMERS`) or short-TTL service tokens are now the **only**
  way to pass `require_private_scope`. With no `PRIVATE_API_CONSUMERS` configured
  every `/private/*` call fails closed (`401`) and the service-token exchange stays
  disabled (`404`); startup logs the misconfiguration loudly (`main.py`).
  `verify_private_api_secret` is removed from `auth_user_service.core.deps`.
  **Migration:** every internal caller must present a per-consumer credential —
  the retirement gate was cleared by every live consumer adopting them (fastapi-m8
  3.1.0 + media-service-m8). `PRIVATE_API_SECRET` itself stays required: it still
  signs the short-TTL service tokens and backs `/health` detail-gating + `/metrics`
  (1.4). `test_consumer_private_auth.py` now asserts the no-registry-denies-all
  fail-closed posture in place of the retired legacy-fallback test.

### Added

- **Per-consumer scoped private-API credentials** (plan item 9.1, near-term —
  issuer side). New `PRIVATE_API_CONSUMERS` setting maps consumer ids → scoped,
  hashed-at-rest secrets. When configured it **replaces** the single shared
  `PRIVATE_API_SECRET` on the private routes: each consumer presents
  `X-Internal-Client` + `X-Internal-Token` and is authorized only for its granted
  scopes (`introspection` / `event-stream` / `user-create`; **deny-by-default**),
  bounding the blast radius to one consumer. `auth_user_service/core/consumer_registry.py`
  builds an `auth_sdk_m8` `ConsumerCredentialRegistry` from config, auto-detecting
  plaintext vs the portable `sha256$<salt>$<digest>` hashed form. The `/private`
  routes are gated per-route by scope via the new
  `auth_user_service.core.deps.require_private_scope`.

- **Short-TTL scoped service tokens** (plan item 9.1, medium-term). New
  `{API_PREFIX}/private/v1/service-token` exchange: a consumer authenticates with
  its bootstrap credential and receives an OAuth-client-credentials-style JWT
  carrying a (narrowable) subset of its granted scopes, presented as
  `Authorization: Bearer <token>` on subsequent private calls. Tokens are signed
  with `PRIVATE_API_SECRET` (HS256), isolated from user tokens by a dedicated
  audience + `type=service` claim, and expire after `SERVICE_TOKEN_TTL_SECONDS`
  (default 300). Rotation comes from the short TTL; the per-consumer bootstrap
  secret rotates rarely. `/metrics` keeps its static scrape credential (no token
  model). `auth_user_service/services/service_token.py`.

- Tests (`tests/security/test_consumer_private_auth.py`) cover the plan's
  required matrix — wrong consumer secret rejected, consumer A cannot use
  consumer B's secret, expired service token rejected, scope violation denied —
  plus the **no-registry fail-closed** posture (every credential shape denied
  `401` once the legacy fallback is retired), the encoded/plaintext loader paths,
  and the exchange route (mint / narrow / escalation-denied / disabled-without-registry).

- **No-downtime `TOKENS_ENCRYPTION_KEY` rotation** (plan item 6.2-pre — the code
  prerequisite that unblocks the 6.2 rotation playbooks). New optional
  `TOKENS_ENCRYPTION_KEY_OLD` setting: when present, `SecurityHelper` builds a
  `MultiFernet([new, old])` so external OAuth token payloads encrypted under the
  previous key stay decryptable (new→old fallback) while new writes use the
  current key — a Fernet key rotation no longer invalidates persisted tokens. The
  key is strength-validated (`secret_keys`) and redacted from debug output
  (`secret_fields`) only when set; unset (the default) keeps single-key behaviour.
  Wired through both persistence call sites (`services/auth.py`,
  `routes/sessions.py`). **`SESSION_SECRET` rotation decision:** accept the
  bounded re-auth window — Starlette's `SessionMiddleware` has no native key-list,
  and the cookie `max_age=3600` already caps a rotation's blast radius to ≤1h of
  re-auth, so no fallback-capable signer is shipped (documented in
  `core/config.py` and `examples/docker_compose/SECURITY.md`). New tests in
  `tests/core/security_test.py` (cross-key decrypt, primary-key-on-write,
  no-fallback failure, single-key `MultiFernet`) and
  `tests/security/test_settings_validators.py` (optional default, strength
  enforcement, `changethis` rejection, debug-output redaction). README env table,
  `.example_env`, every compose `auth.env*` example, and the SECURITY.md secret
  inventory + leaked-key playbook document the dual-key path.

### Changed

- **Example stacks migrated to the per-consumer `1.0.0` issuer image + live-test
  harness alignment (security-tests-m8 ≥ 0.2.0).**
  - `hardened_m8` (base + production overlay) and `vault_dev_m8` now pin the issuer
    image `tepochtli/fa-auth-m8:1.0.0` (was `0.9.9`), so every example stack runs a
    per-consumer issuer (the source-built stacks already did). `1.0.0` ignores the
    legacy single `X-Internal-Token` gate — `PRIVATE_API_CONSUMERS` + per-consumer
    `X-Internal-Client` (or short-TTL service tokens) is the only private-API path.
  - `rs256_m8`: activated the per-consumer config it previously shipped commented —
    `PRIVATE_API_CONSUMERS={"example-api":…}` in `auth.env.example` and
    `INTERNAL_CLIENT_ID=example-api` in `api.env.example`.
  - All stack `test.env` / `test.env.example` and `shared_live_tests/env.example`
    gain `LIVE_TEST_PRIVATE_API_CLIENT_ID=example-api` (sent as `X-Internal-Client`;
    enables the harness F06 legacy-detection check) and a documented, opt-in
    `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` (unlocks the deep `/health` detail via the
    dedicated credential decoupled from `PRIVATE_API_SECRET`). `shared_live_tests`
    README env table aligned.
- **Dependency floors raised for the `auth-sdk-m8 2.1.0` / `fastapi-m8 3.x`
  alignment.** `auth_user_service/requirements_base.txt` now pins
  `auth-sdk-m8>=2.1.0,<3.0.0` (was `>=2.0.0`) and `pydantic_settings>=2.14.2`
  (was `>=2.14.1`). The example consumers move to `fastapi-m8>=3.1.0,<4.0.0`
  (was `>=2.1.0,<3.0.0`; see the per-consumer floor note below) in
  `examples/fastapi_full/requirements_base.txt` (also `pydantic_settings>=2.14.2`)
  and `examples/fastapi_minimal/requirements.txt`.
  `fastapi-m8 3.x` requires `auth-sdk-m8>=2.0.1,<3.0.0` (the consumer floor of
  `3.2.0` raises it to `>=2.1.0`), so the whole stack pins to the single-mount
  `/ping` SDK and the `pydantic-settings 2.14.2` security patch on a single
  shared SDK version. No consumer code changes: the public `fastapi_m8` API surface
  used by the examples is unchanged across the major. Docs aligned to the SDK
  2.0.x single-mount `/ping` (root `README.md` route table + service-triad note,
  and `examples/docker_compose/SECURITY.md` public-route table + bring-up check
  now reference `{API_PREFIX}/ping`). The removed `TOKEN_ALGORITHM` knob was
  already migrated to `ACCESS_TOKEN_ALGORITHM` across every compose stack.
- **Per-consumer credentials are now mandatory for the private API.** The 9.1
  issuer side originally landed additively (legacy single-`PRIVATE_API_SECRET`
  gate kept as an opt-out default); `1.0.0` **retires that fallback** (see
  _Removed — BREAKING_). `PRIVATE_API_CONSUMERS` must be configured for any
  `/private/*` traffic; `PRIVATE_API_SECRET` remains required for service-token
  signing and `/health` + `/metrics` gating.
- **Version bumped to `1.0.0`** across `auth_user_service` (`__version__`), the
  issuer `/meta` `CONTRACT_RANGE` (`>=1.0.0 <2.0.0`, was `>=0.9.9 <0.10.0`), and
  the `fastapi_full` / `fastapi_minimal` example consumers (`__version__` +
  `CONTRACT_RANGE`). `tests/core/test_service_meta.py` asserts the new range.
- **Env examples rewired to the per-consumer model.** Every stateful compose
  stack now ships an **active** issuer `PRIVATE_API_CONSUMERS` entry (`auth.env*`)
  matched by a consumer `INTERNAL_CLIENT_ID` + bootstrap secret (`api.env*`);
  `rs256_m8` (hybrid, revocation off) documents it commented. The `.example_env`,
  the hardened production overlay (`auth.env.production.example` /
  `api.env.production.example`, file-mounted), and the vault prod example are
  aligned. The stale "homelab default / single-secret gate" guidance is removed.
- **Example consumer floor raised to `fastapi-m8>=3.2.0,<4.0.0`** (was `>=3.0.0`)
  in `examples/fastapi_full/requirements_base.txt` and
  `examples/fastapi_minimal/requirements.txt`. The `3.1.0` surface added
  `INTERNAL_CLIENT_ID` + the per-consumer internal-auth path; `3.2.0` adds the
  item-9.4 Design B constant-ungated-`/health` consumer hardening, which the
  example stacks need because `fastapi-public-router` routes `/fastapi/health`
  publicly (no Traefik exclusion) — without the `3.2.0` floor that public body
  would still leak `degraded`. `3.2.0` requires `auth-sdk-m8>=2.1.0,<3.0.0`,
  matched by the issuer's own `>=2.1.0,<3.0.0` pin (one shared SDK version).
- **Docs aligned** (`README.md` route table + env table + Private-API + revocation
  sections; `examples/docker_compose/SECURITY.md` rotation, threat-model, and
  leaked-secret playbook) to the retired gate and the per-consumer model.
- **Public-HTTPS `/health` hardening — constant ungated liveness body** (plan item
  9.4, Design B). The ungated `/health` response is now a constant,
  dependency-independent `{"status":"ok"}` — identical whether Redis/DB are healthy
  or `degraded` (`routes/health.py`). Previously the ungated branch echoed
  `detail["status"]`, which reflected `degraded` and acted as a public timing/state
  oracle for fail-open degradation. Readiness/degradation detection is now
  **credential-only** via the 9.3 `HEALTH_DETAIL_CREDENTIAL` detail gate (unchanged,
  still fail-closed). With the body safe to expose, the Traefik **SECURITY CONTRACT**
  drops `/user/health` from the `auth-public-router` exclusion in all six stacks
  (`dynamic_conf.yml` + `production_dynamic_conf.yml`) so the shallow status is
  publicly reachable; `/user/metrics` + `/user/private` stay internal-only. README +
  `SECURITY.md` route tables, threat model, and bring-up checklist aligned. The
  `fastapi_full` / `fastapi_minimal` example consumers are floored to
  `fastapi-m8>=3.2.0` (the consumer-side Design B release) so their publicly-routed
  `/fastapi/health` is the same constant body — see the dependency-floor note below.
- **User deletion now cascades to owned rows.** `cascade_delete=True` on
  `User → api_keys / rate_limits / sessions` (and `ApiKey → rate_limits`) means
  deleting a user — self-service (`DELETE /profile/delete/me/`) or admin
  (`DELETE /users/delete/{user_id}/`) — removes its owned child rows in the same
  operation instead of leaving orphans or tripping a foreign-key violation
  (`db_models/users.py`, `db_models/api_keys.py`; the FKs already declared
  `ondelete="CASCADE"`). Covered by new cases in `tests/routes/test_profile.py`
  (self-delete) and `tests/routes/test_users.py` (admin delete); the live-test
  suite documents its automatic teardown of throwaway `redteam_*` users.
- **`examples/addon` Chrome-extension template removed.** The browser-extension
  auth example is superseded by the dedicated Vite plugin shipped from the
  `vite-auth-m8` repo; the stale Preact/Vite tree is dropped from this repository.

### Tests

- **Degradation-policy regression suite** (plan item 5.5). New
  `tests/security/test_degradation_policy.py` (7 tests) locks the auth service's
  fail-open/fail-closed contract. Existing resilience suites only verify each
  enforcement point honours a **mocked** `effective_failure_mode`; this suite
  exercises the **real** `AUTH_STRICT_MODE` override on a genuine `Settings`
  instance and proves it drives fail-closed end to end: strict forces every
  per-control mode (`refresh_validation`, `session_write`, `rate_limit`,
  `access_revocation`) to `fail_closed` over explicit `fail_open` settings; with
  Redis down `_check_jti_revocation` returns 503 under strict even when
  `ACCESS_REVOCATION_FAILURE_MODE=fail_open`; a non-strict `fail_open` opt-out
  proceeds but is recorded via `degraded_decision_total` labelled with the real
  effective mode; and the `/health` body's `degradation_modes` reflect the real
  posture (all `fail_closed` under strict). No production code changed.
- **Public-`/health` Design B coverage** (plan item 9.4). `tests/routes/health_test.py`
  adds cases proving the ungated body stays the constant `{"status":"ok"}` even when
  Redis is down (never `degraded`, no detail keys), while the credential-gated detail
  still surfaces `degraded`. `tests/security/test_compose_policy.py` asserts
  `/user/health` is NOT route-excluded (publicly reachable) while `/user/metrics` +
  `/user/private` stay excluded; `tests/security/test_production_overlay.py` updated to
  match. The live `TestF_HealthAPI` (f3) flips from "blocked by Traefik (404)" to
  "public shallow-constant, no detail leak".

## [0.9.9] — 2026-06-22 · Security remediation: hardened compose, app-layer guards, Redis ACLs

> **Requires `auth-sdk-m8 >= 1.5.0` (and `< 2.0.0`)** — pin bumped in
> `auth_user_service/requirements_base.txt`. 1.5.0 dual-mounts the liveness
> `/ping` route (a root `/ping` for direct container/sidecar probes plus a hidden
> `{prefix}/ping` copy that stays reachable behind a prefix-routing proxy); the
> 2.0.0 line is a breaking single-mount change and is intentionally excluded.

### Added

- **Live exposure-matrix tests** (plan item 5.2) — `tests/live/test_compose_exposure_matrix.py`,
  a topology-parameterized live suite that asserts the public/internal route-exposure
  contract against a running compose stack. Table-driven allow/deny lists selected by
  `EXPOSURE_TOPOLOGY={case_a|case_b}` (default `case_b`, matching the shipped `hardened_m8`
  example that routes both `/user` and `/fastapi` publicly). Case A (UI-only/closed)
  additionally asserts no backend microservice route (`/fastapi/*`) is public on its own.
  Asserted in **both** topologies: `/user/private/*`, `/user/metrics` + `/fastapi/metrics`
  (no Prometheus body), the *detailed* `/health/` body (shallow `{"status"}` may answer
  publicly; infra detail is token-gated per 1.4), and infra surfaces (Traefik dashboard/API).
  Internal positive/negative controls verify `/user/private/v1/jti-status` is reachable on
  the loopback services entryPoint only with a valid `X-Internal-Token`. The module
  auto-skips when the stack is unreachable and is excluded from the coverage gate
  (`--ignore=tests/live`); 21 tests, ruff + mypy + bandit green; 754 unit/security tests,
  100% cov.

- **Compose hardening-policy tests** (plan item 5.1) — static assertions that lock
  in the `hardened_m8` container security contract:
  (1) app services (`auth_user_service`, `fastapi_full`) carry the required
  hardening flags (`cap_drop: ALL`, `no-new-privileges:true`, `read_only: true`,
  `tmpfs: [/tmp, /run]`) in the dev base;
  (2) data/observability services (`m8_db`, `redis_cache`, `prometheus`, `grafana`)
  bind only to `127.0.0.1` in the dev compose (no all-interface exposure);
  (3) both the dev (`dynamic_conf.yml`) and production (`production_dynamic_conf.yml`)
  Traefik configs explicitly exclude `/user/private` and `/user/metrics` from the
  public `auth-public-router` rule. Docker-socket absence, image-pin policy, and
  production-overlay data-port-reset are not duplicated (covered by
  `test_socketless_traefik.py`, `test_image_pins.py`, and `test_production_overlay.py`).
  Covered by `tests/security/test_compose_policy.py` (16 tests). 754 tests, 100% cov,
  ruff + mypy + bandit green.

- **Image-pin policy enforced in hardened/production compose** (plan item 4.1) — bare
  `alpine` image (no version tag) replaced with `alpine:3.22` across all six compose
  example stacks (`hardened_m8`, `metrics_m8`, `postgres_m8`, `quickstart_m8`, `rs256_m8`,
  `vault_dev_m8`). Static policy tests added in
  `tests/security/test_image_pins.py` (4 tests) assert that every image in the
  `hardened_m8` base and production overlay declares an explicit version tag (no bare
  images) and does not use the mutable `:latest` tag. Services using `build:` are
  excluded. All previously pinned third-party images (`traefik:v3.7.5`,
  `postgres:18.4-alpine`, `redis:8.8.0-alpine`, `ubuntu/prometheus:3.11-26.04_stable`,
  `grafana/grafana:13.1.0-25530058790`, `tepochtli/fa-auth-m8:0.9.9`) continue to pass
  the new assertions. 717 tests, 100% cov, ruff + mypy + bandit green.

- **Vault example renamed and constrained** (plan item 2.3) — `vault_m8` renamed to
  `vault_dev_m8` to make the ephemeral, dev-mode-only nature explicit in the directory
  name. Preflight now hard-fails when either `VAULT_DEV_TOKEN` is present in an env
  file **or** a compose service uses the Vault `-dev` flag, both under
  `ENVIRONMENT=production`. A new non-runnable `vault_prod_template/` directory provides
  annotated templates for connecting the auth service to a production-grade Vault:
  `vault/config/vault.hcl` (Raft storage, TLS enabled), `vault/policies/app-policy.hcl`
  (read-only scoped policy), and `docker-compose.app.yml.template` (app token via Docker
  secret file, no `VAULT_DEV_TOKEN`). All README files updated with the rename and
  cross-references. Covered by `tests/security/test_vault_dev_constrained.py` (16 tests).

- **Production overlay for `hardened_m8`** (plan item 2.1) — a thin
  `docker-compose.production.yml` applied on top of the dev base
  (`docker compose -f docker-compose.yml -f docker-compose.production.yml up`,
  Compose v2.24+ for the `!reset`/`!override` tags). One stack, two postures: the
  dev/home-lab default is unchanged and nothing dangerous is default-on; the
  overlay flips on production hardening — `ENVIRONMENT=production` +
  `STRICT_PRODUCTION_MODE=true` via new `auth.env.production.example` /
  `api.env.production.example` / `.env.production.example` (all secrets stay the
  fail-closed `changethis` placeholder), docs off, `SESSION_COOKIE_SECURE=true`,
  FQDN host rules (`traefik/production_dynamic_conf.yml`) backed by app-layer
  `ALLOWED_HOSTS`, `cert-init` downgraded from a self-signed generator to a
  fail-closed cert **presence check**, only `:80` (HTTP→HTTPS redirect) and
  `:443` published (no host-published dashboard/internal `:9000`/DB/Redis/
  Prometheus/Grafana ports, via `!reset []`), and pinned images. **Migration
  decision:** auto-`alembic upgrade head` on `up` is kept for the single-node
  overlay (idempotent + pinned images); a one-shot pre-start command is
  documented for multi-replica/zero-downtime rollouts. Documented in the README
  production section and locked by `tests/security/test_production_overlay.py`.
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

- Raised the `/meta` compatibility contract range lower bound to
  `>=0.9.9 <0.10.0` (was `>=0.9.8 <0.10.0`) in
  `auth_user_service/core/service_meta.py` so consumers pin to the hardened
  security baseline. `CONTRACT_VERSION` stays `0.9`; `/meta` + `/ping` are
  unchanged on the wire.
- Bumped the `auth-sdk-m8` dependency to `>=1.5.0,<2.0.0` (was `>=1.4.0`) in
  `auth_user_service/requirements_base.txt`, aligning the issuer with the rest
  of the fleet (`fastapi-m8` pins the same range) and capping below the breaking
  `2.0.0` single-mount `/ping` change.
- Pinned the example consumers to `fastapi-m8>=2.1.0,<3.0.0` (was `>=2.0.0`) in
  `examples/fastapi_full/requirements_base.txt` and
  `examples/fastapi_minimal/requirements.txt`. `fastapi-m8` 2.0.0 depends on
  `auth-sdk-m8>=1.4.0`, which lets a shared-env install downgrade the SDK below
  1.5.0 and lose the dual-mounted `/ping`; 2.1.0 depends on
  `auth-sdk-m8>=1.5.0,<2.0.0`, keeping the SDK aligned.
- Grafana admin credentials moved out of the committed
  `grafana/config.monitoring` into a gitignored `grafana.env` loaded via
  `env_file`. Pinned the `fa-auth-m8` image to `0.9.9` (was `:latest`) in the
  hardened and vault example stacks.
- Lowered the `redis` requirement floor to `>=5.3.1` to match the tested
  runtime; no security advisory requires the 8.x line.

### Fixed

- Typed the redis sync client responses (`get`/`getdel`/`incr`) in
  `auth_user_service/core/client.py` so `mypy auth_user_service` is clean.

### Security

- **OAuth redirect-prefix pinning required in production** (plan item 8.2). When
  `ENVIRONMENT` is `production`/`staging` or `STRICT_PRODUCTION_MODE=true`, the
  OAuth login flow now rejects `chrome-extension://` redirect targets at request
  time (`400`) unless `OAUTH_ALLOWED_REDIRECT_PREFIXES` pins the trusted callback
  origins. Without pinning, any installed extension could receive issued OAuth
  tokens (open public-client risk); the gate makes pinning mandatory in
  prod/strict and advisory in local/dev. `_validate_redirect_target` gained a
  hardened prod/strict detection guard. `hardened_m8/auth.env.production.example`
  documents the requirement with `OAUTH_ALLOWED_REDIRECT_SCHEMES` /
  `OAUTH_ALLOWED_REDIRECT_PREFIXES` placeholders. Covered by
  `tests/security/test_oauth_redirect_policy.py` (7 tests).
- **App-layer Host-header validation** (plan item 5.3). `auth_user_service/main.py`
  now wires Starlette's `TrustedHostMiddleware` whenever `ALLOWED_HOSTS` is set
  (mirroring the fastapi-m8 consumer pattern), so a host allowlist is enforced at
  the app layer and survives a reverse-proxy swap or misconfiguration. Non-prod
  envs auto-inject `testserver` for test clients; production and
  `STRICT_PRODUCTION_MODE` require every FQDN to be listed explicitly. Covered by
  `tests/security/test_host_header_routing.py` (12 tests).
- **`API_BIND_IP=0.0.0.0` production gate codified** (plan item 5.4). Static
  compose-policy tests assert every dev-base stack binds port 9000 via
  `${API_BIND_IP:-127.0.0.1}` (never a hardcoded `0.0.0.0`), the production
  overlay drops port 9000 from published ports entirely, and no `*.env.example`
  sets `API_BIND_IP=0.0.0.0`. A preflight test pins the break-glass path
  (`ALLOW_PUBLIC_API_BIND=true` permits a public bind in production; rejection
  without it was already covered). `tests/security/test_api_bind_ip.py` (plus a
  preflight case in `tests/security/test_preflight_security.py`).
- **Per-service Redis ACLs (least privilege)** (plan item 6.x.1). Every compose
  example's `redis_cache` bootstrap replaces the open `appuser ~* +@all` with a
  scoped `auth` user — restricted to exactly the key prefixes the service writes
  (`oauth_session:*`, `auth_code:*`, `login:*`, `refresh:*`, `exchange:*`, `rt:*`,
  `jwt:blacklist:*`, `rate:*`, `api_key:*`) and only the command categories it
  uses (`+@read +@write +@transaction +@connection +eval -@dangerous`; the
  refresh-rotation Lua `EVAL` is the sole scripting grant). The always-present
  `default` user is stripped to `resetkeys -@all +@connection -@dangerous`, so it
  keeps the healthcheck `PING` but can no longer read, write, or flush any data.
  `REDIS_USER` in the auth env examples moves from `appuser` to `auth`. A leaked
  auth Redis credential is now confined to the auth service's own keyspace.
  Locked by `tests/security/test_redis_acl_policy.py` (37 static assertions across
  all six example stacks: no open ACL, scoped key patterns, category allow/deny,
  default-user lockdown, env wiring, and a source-linked guard that fails if a new
  Redis key prefix is added without extending the ACL).
- **Runtime secrets can be sourced from mounted files** (plan item 6.1). The
  service `Settings` inherits the Docker/K8s `<FIELD>_FILE` convention from
  `auth_sdk_m8.core.config.CommonSettings` — no service-side code is added. For
  any field `FOO` (service-declared like `PRIVATE_API_SECRET`, `SESSION_SECRET`,
  `TOKENS_ENCRYPTION_KEY`, `METRICS_SCRAPE_CREDENTIAL`, or inherited like
  `DB_PASSWORD`/`EVENT_SIGNING_KEY`), setting `FOO_FILE` to a readable path makes
  the file's stripped contents the value of `FOO`, outranking a plaintext
  `.env`/env value (init kwargs still win) and failing closed if the path is
  missing. This is the mechanism the production overlay (item 2.1) uses to mount
  secrets under `/run/secrets/*` instead of inlining them. The inheritance is
  locked in at the service layer by `tests/security/test_config_file_secrets.py`
  (8 tests across both MRO origins; precedence, fail-closed, and `SecretStr`
  masking asserted). Full secret-manager migration + rotation playbooks (6.2)
  remain P3.
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
- **Socketless Traefik production path locked in** (plan item 2.2). The production
  path (the dev base merged with `docker-compose.production.yml`, or
  `production_dynamic_conf.yml` copied over `dynamic_conf.yml`) routes through the
  Traefik **file provider only** and never mounts `/var/run/docker.sock` — backends
  resolve over Docker DNS by container name, so no socket and no per-container
  `traefik.*` discovery labels are required. The structural guarantee established by
  item 0.3 is now codified by `tests/security/test_socketless_traefik.py` (no socket
  mount on the production path, file-provider-only static config, no discovery
  labels, and every file-provider router resolving to a defined container-DNS
  backend) so a future edit cannot silently re-introduce the Docker provider. The
  hardened-stack README production section documents the contract. The shared
  compose-parsing helpers were factored into `tests/security/_compose.py`.

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
  `hardened_m8` (container hardening + Docker Hub image), `vault_dev_m8` (HashiCorp Vault dev mode).
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
