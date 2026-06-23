# Security — fa-auth-m8 Docker Compose Examples

Operational security reference for the example stacks in `examples/docker_compose/`.

For the underlying SDK security model (cryptographic primitives, config-health guards, app-layer
access guards, per-consumer credential verification) see the
[auth-sdk-m8 SECURITY.md](https://github.com/mano8/auth-sdk-m8/blob/main/SECURITY.md).

---

## Trust model

`fa-auth-m8` is the **authentication authority** for the stack. It owns:

- Token issuance — access tokens (HS256 / RS256 / ES256), refresh tokens, and JWKS publication.
- Session state — the Redis JTI blacklist, refresh-token allowlist, and PKCE code store.
- Event delivery — the SSE bridge (`/private/v1/events/stream`) that pushes `session-revoked` /
  `user-deleted` events to consumers.
- The private API (`/private/*`) — all inter-service operations are gated behind `X-Internal-Token`.

**What fa-auth-m8 does NOT own:**

- Consumer token validation — consumers call `auth-sdk-m8` / `fastapi-m8` locally; no per-request
  round trip to this service.
- Media storage or MinIO. Those controls live in `media-service-m8`; this stack has no object store.
- Network-layer controls. TLS termination, IP routing, and load balancing are delegated to Traefik.
  The app-layer guards (`X-Internal-Token`, `make_internal_token_authorizer`,
  `make_scrape_credential_guard`) are the **primary** access control regardless of proxy config.

### Deployment topologies

The compose examples support two public topologies (choose one before going to production):

- **Case A — UI-only / closed (most secure, default hardened posture).** Only the UI or gateway is
  public. The auth service and consumer sit on `m8_app_network` only; private/internal/metrics APIs
  never leave the Docker network.
- **Case B — external clients.** Selected services are published over HTTPS (e.g. a Chrome
  extension calling the auth service directly). `/private/*` and `/metrics` remain internal; only
  shallow `{API_PREFIX}/ping` is externally reachable as a liveness probe.

### Container network topology (`hardened_m8`)

```text
Internet
    │
    ▼ :80 (HTTP → HTTPS redirect) / :443 (HTTPS)
 Traefik  ──── websecure entryPoint
    │               (public routes only — see Route inventory below)
    │
    ├── /user/*  →  auth_user_service :8000
    └── /fastapi/* → fastapi_full :8000
         │                │
         └──── m8_app_network (internal Docker network)
                    │
           ┌────────┴────────┐
           ▼                 ▼
       m8_db             redis_cache
   (PostgreSQL)       (Redis — auth only)

 Traefik  ──── api entryPoint :9000  (loopback-bound)
    │           health detail / metrics / private API
    └── /user/private/*       (X-Internal-Token required)
        /user/health/ detail  (X-Internal-Token required for full body)
        /user/metrics         (internal only + optional scrape credential)

 Traefik dashboard  :8080  (loopback-bound, dev only — removed in production overlay)
 Prometheus         :9090  (loopback-bound)
 Grafana            :3000  (loopback-bound)
 Database           :5432  (loopback-bound)
 Redis              :6379  (loopback-bound)
```

---

## Route inventory

### Public routes (websecure / internet-facing)

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `{API_PREFIX}/ping` | — | Dependency-free liveness; single-mounted under the prefix (auth-sdk-m8 2.0.0) |
| GET | `{API_PREFIX}/meta` | — | Service/version identity for client compat checks |
| GET | `{API_PREFIX}/health/` | — | Shallow `{"status":...}` only; full infra detail requires `X-Internal-Token` |
| GET | `{API_PREFIX}/.well-known/jwks.json` | — | JWKS (RS256/ES256 public key) |
| POST | `{API_PREFIX}/login/access-token` | — | Email + password → access token + refresh cookie |
| POST | `{API_PREFIX}/login/refresh-token/` | — | Rotate refresh cookie → new access token |
| POST | `{API_PREFIX}/login/logout/` | JWT | Revoke session, blacklist JTI, clear cookie |
| POST | `{API_PREFIX}/login/test-token/` | JWT | Validate access token, return current user |
| GET | `{API_PREFIX}/google-api/login-url/` | — | Return Google OAuth2 authorization URL |
| POST | `{API_PREFIX}/google-api/exchange/` | — | Auth-code exchange (PKCE verified, atomic GETDEL) |
| GET | `{API_PREFIX}/google-auth/oauth-callback/` | — | Google OAuth2 PKCE callback |
| GET | `{API_PREFIX}/profile/*` | JWT | Self-service profile read/update/delete |
| POST | `{API_PREFIX}/profile/api-keys/` | JWT | Create API key |
| GET/DELETE | `{API_PREFIX}/profile/api-keys/{id}` | JWT | List/revoke API keys |
| GET | `{API_PREFIX}/profile/api-keys/verify` | X-API-Key | Validate key, enforce rate limits |
| GET | `{API_PREFIX}/sessions/*` | JWT / superuser | Session management |
| GET/POST/PATCH/DELETE | `{API_PREFIX}/users/*` | superuser | User CRUD |
| GET | `{API_PREFIX}/dashboard/*` | JWT | Activity stats |

### Internal-only routes (api entryPoint :9000 or excluded from public router)

These routes **must not appear on the `websecure` public entryPoint**. The Traefik file provider
excludes them via explicit `PathPrefix` deny rules in `dynamic_conf.yml` and
`production_dynamic_conf.yml`; the app-layer guards are the primary enforcement.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| POST | `{API_PREFIX}/private/users/` | X-Internal-Token | Create user (inter-service) |
| POST | `{API_PREFIX}/private/v1/jti-status` | X-Internal-Token | JTI revocation check |
| GET | `{API_PREFIX}/private/v1/events/stream` | X-Internal-Token | SSE bridge for revocation events |
| GET | `{API_PREFIX}/private/v1/service-token` | X-Internal-Token | Short-TTL service token exchange (9.1) |
| GET | `{API_PREFIX}/health/` (detail body) | X-Internal-Token | Full infra detail (Redis, DB, degradation modes) |
| GET | `{API_PREFIX}/metrics` | scrape credential (optional) | Prometheus metrics |
| GET | `{API_PREFIX}/docs` / `/redoc` / `/openapi.json` | — | Suppressed in production (`SET_DOCS=false`) |

---

## Secret inventory

| Secret | Env var | Holder | Blast radius if leaked | Rotation priority |
| --- | --- | --- | --- | --- |
| Access signing key (HS256) | `ACCESS_SECRET_KEY` | auth service only | Any holder forges valid access tokens | **Immediate** |
| RSA/EC private key | `ACCESS_PRIVATE_KEY_FILE` (path) | auth service only | Forge access tokens; sign a rogue JWKS | **Immediate** |
| Refresh signing key | `REFRESH_SECRET_KEY` | auth service only | Forge refresh tokens, bypass rotation | **Immediate** |
| Old refresh signing key | `REFRESH_SECRET_KEY_OLD` | auth service only (rotation window) | Same as above during window | Remove when window expires |
| Session middleware key | `SESSION_SECRET` | auth service only | Forge session middleware cookies | **Immediate** |
| Fernet payload key | `TOKENS_ENCRYPTION_KEY` | auth service only | Decrypt token payloads in Redis | **Immediate** |
| Event signing key | `EVENT_SIGNING_KEY` | auth service + all consumers | Forge revocation SSE frames → corrupt consumer caches | **Immediate; rotate all together** |
| Shared private-API secret | `PRIVATE_API_SECRET` | auth service + registered consumers | Call any `/private/*` operation | **Immediate; 9.1 per-consumer credentials reduce blast radius** |
| DB password | `DB_PASSWORD` | auth service only | Read/write user, session, auth-code, API-key tables | **Immediate** |
| Redis ACL password | `REDIS_PASSWORD` | auth service only | Read/write JTI blacklist, refresh allowlist, rate-limit keys | **Immediate** |
| Prometheus scrape credential | `METRICS_SCRAPE_CREDENTIAL` | auth service + Prometheus | Unauthorized metrics reads | Rotate promptly |
| Bootstrap superuser password | `FIRST_SUPERUSER_PASSWORD` | ops (used once) | Superuser takeover on first boot if not rotated | Change immediately after first login |
| Google OAuth2 client secret | `GOOGLE_CLIENT_SECRET` | auth service only | Impersonate the OAuth2 client | **Immediate** |
| Per-consumer credential | `PRIVATE_API_CONSUMERS` entries | auth service credential map | Call scoped `/private/*` for that consumer only | Rotate individual entry; no fleet-wide impact |

> **Key separation invariant.** `SESSION_SECRET` and `TOKENS_ENCRYPTION_KEY` must be distinct values
> so rotating the session key does not invalidate encrypted tokens stored in Redis.

---

## Attacker paths

| Path | Entry point | Mitigated by |
| --- | --- | --- |
| Forge arbitrary JWTs | Stolen `ACCESS_SECRET_KEY` or RS256 private key | App-layer `iss`/`aud` enforcement + JTI blacklist; key rotation (see playbook) |
| Replay stolen access token | JWT from a leaked log or HTTPS interception | JTI blacklist (`stateful` mode); short TTL (`ACCESS_TOKEN_EXPIRE_MINUTES`); HTTPS mandatory |
| Replay stolen refresh cookie | HttpOnly refresh cookie | Cookie is `HttpOnly`; `SESSION_COOKIE_SECURE=true` in production; each rotation re-issues a new token and blacklists the old JTI |
| JTI-blacklist suppression | Redis write access | Scoped Redis ACL (auth user restricted to `rt:* jwt:blacklist:* oauth_session:* login_rate:* refresh_rate:*`); Redis not exposed on host interfaces |
| Forge revocation events | Stolen `EVENT_SIGNING_KEY` | HMAC signature verification on every SSE frame; fail-closed on bad signature; see event-signing playbook |
| Call `/private/*` without authorization | Missing or wrong `X-Internal-Token` | `make_internal_token_authorizer` guard (app-layer, constant-time); Traefik `PathPrefix(/user/private)` excluded from `websecure`; `api` entryPoint loopback-bound |
| Read full health detail | Anonymous `/health/` call | `make_internal_token_authorizer` gates the detail body; anonymous callers receive shallow `{"status":...}` only |
| Scrape Prometheus metrics | Unauthorized `/metrics` call | `make_scrape_credential_guard` (optional; network boundary is the baseline); `api` entryPoint loopback-bound |
| Container → host pivot | Docker socket exposure | `hardened_m8` uses file-provider only — no socket mount on the Traefik container (verified by `test_socketless_traefik.py`) |
| Google OAuth redirect hijack | Manipulated `redirect_target` | `OAUTH_ALLOWED_REDIRECT_PREFIXES` enforced in production/strict; plain HTTP redirects blocked unless localhost |
| Brute-force login | Repeated `POST /login/access-token` | Per-email rate limiting (`LOGIN_RATE_LIMIT_REQUESTS` / `LOGIN_RATE_LIMIT_WINDOW_MINUTES`); Redis-backed fixed window |
| Token cross-service reuse | Access token issued by another service | `TOKEN_ISSUER` + `TOKEN_AUDIENCE` strict binding rejects tokens from a different issuer or intended for a different audience |
| Superuser account takeover | Weak `FIRST_SUPERUSER_PASSWORD` | Boot-time password-strength validator; change immediately after first login |
| `:latest` image substitution | Supply chain / registry attack | All images in `hardened_m8` pinned by tag; production overlay never uses `:latest`; `test_image_pins.py` enforces this |

---

## Production checklist

Run through this checklist **before** bringing up the production overlay.

### 1 — Secrets

- [ ] Replace every `changethis` in `.env`, `auth.env`, `api.env`, and all
  `*.production.example` copies with a strong random value
  (`python -c "import secrets; print(secrets.token_urlsafe(64))"`).
- [ ] Ensure `SESSION_SECRET` ≠ `TOKENS_ENCRYPTION_KEY` (key separation).
- [ ] Set `EVENT_SIGNING_KEY` to the same non-placeholder value in `auth.env` and in every
  consumer stack's env file.
- [ ] Set `PRIVATE_API_SECRET` to the same non-placeholder value in `auth.env` and every
  consumer's `api.env` (or provision `PRIVATE_API_CONSUMERS` per-consumer credentials for 9.1).
- [ ] Confirm `FIRST_SUPERUSER_PASSWORD` satisfies the strength policy
  (`PASSWORD_REGEX` enforced at boot).
- [ ] If Google OAuth is enabled, confirm `GOOGLE_CLIENT_SECRET` is a real client secret,
  `OAUTH_ALLOWED_REDIRECT_PREFIXES` is set, and `GOOGLE_OAUTH_REDIRECT_URI` matches the Google
  Console exactly.

### 2 — Domain and TLS

- [ ] Set a real FQDN in `DOMAIN`, `BACKEND_HOST`, `FRONTEND_HOST`, `TOKEN_ISSUER`, and
  `TOKEN_AUDIENCE`; remove all `localhost` values from `ALLOWED_ORIGINS`.
- [ ] Set `ALLOWED_HOSTS` to the FQDN list (at a minimum the auth service FQDN).
- [ ] Provision real TLS certificates at `traefik/certs/local.crt` + `local.key`. The production
  overlay's `cert-init` is a **fail-closed presence check** — it aborts if the files are missing.
- [ ] Update `traefik/production_dynamic_conf.yml` `Host()` rules to your FQDN.
- [ ] Enable `HSTS_ENABLED=true` **only** after TLS is stable and the hostname will remain
  HTTPS-only for the full `HSTS_MAX_AGE` period (browser-persisted, hard to reverse).

### 3 — Apply the overlay

```bash
cd examples/docker_compose/hardened_m8
cp .env.production.example .env
cp auth.env.production.example auth.env.production
cp api.env.production.example api.env.production
# Fill every `changethis`; set real FQDN values
bash init.sh
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

Requires Docker Compose **v2.24+** for the `!reset` / `!override` merge tags.

### 4 — Validate before opening traffic

- [ ] Run `security-tests-m8 preflight --deployment-root .` — fix any fatal findings.
- [ ] Confirm the service comes up: `curl -k https://<fqdn>{API_PREFIX}/ping` → `{"status":"ok"}`.
- [ ] Confirm docs are suppressed: `curl -k https://<fqdn>/user/docs` → 404 or redirect.
- [ ] Confirm `/user/private/*` is not reachable on `websecure`:
  `curl -k https://<fqdn>/user/private/v1/jti-status` → 404.
- [ ] Confirm `/user/metrics` is not reachable on `websecure`:
  `curl -k https://<fqdn>/user/metrics` → 404.
- [ ] Confirm anonymous `/user/health/` returns only `{"status":...}` (no Redis/DB detail).
- [ ] Run the full live security suite:
  `security-tests-m8 run --env-file test.env --include-destructive` (against a non-production
  clone if possible, since destructive tests create and delete users).

### 5 — Ongoing

- [ ] Keep all images pinned; update pins when you pull a new release.
- [ ] Rotate secrets on a schedule or after any suspected exposure (see playbooks below).
- [ ] Monitor `auth_degraded_decision_total` and `auth_redis_circuit_breaker_open` metrics for
  Redis availability signals.
- [ ] Remove the dedicated `security-tests-m8` superuser after each live-test run.

---

## Incident response

### Legend

Each playbook follows: **Detection → Containment → Rotation / Redeploy → User impact →
Validation → Rollback**.

### Leaked access-token signing key (`ACCESS_SECRET_KEY` or `ACCESS_PRIVATE_KEY_FILE`)

**Detection.** Unusual API activity originating from unknown clients; JWTs in logs whose
`iat`/`exp` do not match expected issuance patterns; external vulnerability disclosure.

**Containment.** Generate a new key immediately:
- HS256: `python -c "import secrets; print(secrets.token_urlsafe(64))"`
- RS256: `openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -pubout -out public.pem`

Replace the value in `auth.env` (and update `ACCESS_PRIVATE_KEY_FILE` mounts for asymmetric
stacks). Redeploy the auth service:
```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --no-deps auth_user_service
```

**Rotation / Redeploy.** After the auth service restarts with the new key:
- RS256: wait for `JWKS_CACHE_TTL_SECONDS` (default 300 s) to expire on every consumer, or
  restart them to force an immediate JWKS re-fetch.
- Wipe all active sessions to force re-authentication (optional but recommended if exposure
  duration is unknown):
  ```bash
  docker exec <redis_container> redis-cli -u redis://<auth_user>:<password>@localhost:6379 --no-auth-warning \
    KEYS "rt:*" | xargs redis-cli DEL
  docker exec <redis_container> redis-cli ... KEYS "jwt:blacklist:*" | xargs redis-cli DEL
  docker exec <redis_container> redis-cli ... KEYS "oauth_session:*" | xargs redis-cli DEL
  ```

**User impact.** All active access tokens are immediately invalidated (new key rejects old
signatures). Users are prompted to log in again. If sessions are wiped, all refresh cookies also
become invalid.

**Validation.** Issue a new access token and confirm it is accepted. Attempt to present a token
signed with the old key — it must return `401 Unauthorized`.

**Rollback.** The old key cannot be re-enabled without re-exposing the compromised credential.
If the rotation caused unexpected breakage (e.g., consumer not updated), restart consumers with
the new `ACCESS_PUBLIC_KEY_FILE` / `JWKS_URI` before re-enabling traffic.

---

### Leaked refresh signing key (`REFRESH_SECRET_KEY`)

**Detection.** Refresh tokens accepted after being revoked; anomalous long-lived sessions;
external report.

**Containment.** Zero-downtime rotation path: set the new value as `REFRESH_SECRET_KEY` and move
the old value to `REFRESH_SECRET_KEY_OLD` in `auth.env`. Redeploy the auth service.

**Rotation / Redeploy.** During the window (`REFRESH_TOKEN_EXPIRE_MINUTES`), existing refresh
tokens signed with the old key validate via the fallback. Once the window closes, remove
`REFRESH_SECRET_KEY_OLD` and redeploy.

For immediate containment (at the cost of forcing all users to re-login): wipe `rt:*` in Redis
before redeploying.

**User impact.** With the zero-downtime path: no disruption during the window; users are
prompted to re-authenticate once `REFRESH_SECRET_KEY_OLD` is removed. With the immediate wipe:
all active sessions invalidated.

**Validation.** Issue a refresh token under the new key; confirm the old key no longer signs
valid tokens (no `REFRESH_SECRET_KEY_OLD` present).

**Rollback.** If the new key causes unexpected issues, revert to the old key in
`REFRESH_SECRET_KEY` and redeploy.

---

### Leaked event-signing key (`EVENT_SIGNING_KEY`)

**Detection.** `auth_event_stream_events_total{result="dropped_sig_fail"}` metric rising
unexpectedly; false logout bursts (forged `session-revoked` frames); consumers failing to evict
valid sessions (suppressed `user-deleted` frames); external report.

**Impact.** An attacker with the key can forge revocation events, causing consumers to flush
valid sessions (false logouts) or suppress legitimate revocations (tokens accepted longer than
they should be). Token issuance is unaffected.

**Containment.** Set `EVENT_SIGNING_ACCEPT_UNSIGNED=true` on every consumer and
`EVENT_SIGNING_ENABLED=false` on the publisher. This disables signing while you distribute the
new key.

**Rotation / Redeploy.** Generate a new key and deploy it to every service simultaneously
(auth service `auth.env` + every consumer `api.env`). Re-enable signing
(`EVENT_SIGNING_ENABLED=true`) and flip `EVENT_SIGNING_ACCEPT_UNSIGNED=false` on consumers.

**User impact.** None if the rollout window is kept short. Consumers in `fail_closed` mode may
briefly return 503 if the signing key update is not atomic across the fleet.

**Validation.** `auth_event_stream_events_total{result="dropped_sig_fail"}` reaches zero once
all publishers sign with the new key and all consumers verify with it.

**Rollback.** Revert to `EVENT_SIGNING_ACCEPT_UNSIGNED=true` on consumers if the new key
deployment fails mid-rollout.

---

### Leaked `PRIVATE_API_SECRET` (shared model)

**Detection.** Unexpected calls to `/private/v1/jti-status` or the SSE stream from unknown
sources in the Traefik access log; external report.

**Impact.** Any holder can call `/private/*` endpoints — JTI introspection and the event stream.
They cannot forge tokens or read the database directly. If 9.1 per-consumer credentials are in
use, blast radius is one consumer.

**Containment.** Rotate the value in `auth.env` **and every registered consumer** `api.env`
simultaneously. Redeploy all services.

**Longer-term hardening.** Provision per-consumer credentials via `PRIVATE_API_CONSUMERS`
(Phase 9.1 issuer-side). Each consumer then holds its own secret; rotating one does not require
touching all others.

**User impact.** Brief unavailability on the private API during the simultaneous redeploy window.
No user-visible sessions or tokens are affected.

**Validation.** Attempt to call `/private/v1/jti-status` with the old secret — expect `401`.
Confirm the consumer service reconnects with the new credential.

**Rollback.** If the redeploy fails for a consumer, it will return 401 on every private-API
call until it is updated. Revert the consumer's `api.env` temporarily if needed.

---

### Leaked `TOKENS_ENCRYPTION_KEY`

**Detection.** Unexpected decryption of Redis payloads; external report.

**Impact.** An attacker with this Fernet key can decrypt token payloads stored in Redis
(refresh-token allowlist entries, PKCE auth codes, external OAuth tokens). Tokens in flight
and the database are unaffected.

**Containment.** Rotate the key in `auth.env`. Redeploy. All existing Redis payloads encrypted
with the old key become unreadable — treating this as a full session wipe (wipe `rt:*`,
`oauth_session:*` in Redis) prevents confusion from decrypt failures.

**User impact.** All active refresh tokens and in-progress OAuth sessions invalidated; users
must re-authenticate.

**Validation.** Issue a new refresh token; confirm it validates successfully. Confirm old-key
Redis entries are gone.

**Rollback.** Revert `TOKENS_ENCRYPTION_KEY` to the old value only if you can confirm the key
was not actually exposed — this re-exposes old-key payloads.

---

### Leaked database password (`DB_PASSWORD`)

**Detection.** DB audit logs showing unexpected reads/writes; external report.

**Containment.** Change the database user password immediately in the DB and in `auth.env`.
Redeploy the auth service.

**Audit.** Review DB audit logs for unauthorized access to the `user`, `session`, `auth_code`,
`refresh_token`, and `api_key` tables. If write access was exploited, treat all active sessions
and issued tokens as potentially compromised and follow the access-signing-key rotation playbook.

**User impact.** Service unavailability during the redeploy window. If write access was confirmed,
force re-authentication for all users.

**Validation.** Confirm the auth service connects with the new credential (`/user/health/` shows
`"database":"ok"`). Confirm the old credential is rejected at the DB level.

**Rollback.** Revert the DB password change only if the new credential cannot be deployed (then
treat the exposure as ongoing and rotate again immediately).

---

### Leaked Redis ACL credential (`REDIS_PASSWORD`)

**Detection.** Unexpected Redis client connections in Redis logs; anomalous key-prefix
reads/writes; external report.

**Containment.** Change the ACL user password:
```bash
docker exec <redis_container> redis-cli -u redis://<auth_user>:<old_password>@localhost:6379 \
  ACL SETUSER auth on ><new_password> ...
```
Update `REDIS_PASSWORD` in `auth.env` and `.env`. Redeploy.

**Audit.** An attacker with the scoped `auth` ACL credential can read/write `rt:*`
(refresh-token allowlist), `jwt:blacklist:*` (JTI blacklist), `oauth_session:*` (auth-code
sessions), and `login_rate:*` / `refresh_rate:*` (rate-limit counters). Treat all active
sessions as potentially compromised — wipe the relevant prefixes and force re-authentication.

**User impact.** All active refresh tokens and in-progress OAuth sessions invalidated during the
wipe; users must re-authenticate.

**Validation.** Confirm the auth service reconnects to Redis (`/user/health/` shows `"redis":"ok"`
and `"circuit_breaker":"closed"`). Confirm the old credential is rejected.

**Rollback.** If the new credential cannot be deployed, revert the ACL password change (treat the
exposure as ongoing).

---

### Redis data loss or wipe

**Detection.** Auth service logs `CRITICAL: Redis unavailable`; `/user/health/` shows
`"redis":"unavailable"`; `auth_redis_circuit_breaker_open` gauge → 1.

**Impact.** With the default `fail_closed` posture for refresh validation and session writes:
all refresh token validations return 503 and all logout attempts return 503 until Redis
recovers. Rate limiting and access-token revocation fail open (short access-TTL bounds
exposure). If the Redis data directory is wiped entirely, all refresh tokens and JTI blacklist
entries are gone — a window exists where previously-revoked JTIs could be replayed until they
expire naturally (bounded by `ACCESS_TOKEN_EXPIRE_MINUTES`).

**Containment.** Restore Redis from a backup or let it recover. If no backup is available:
1. Accept the brief replay window for access tokens (bounded by TTL).
2. Force re-authentication for high-value users via the `DELETE /sessions/delete-by-user/{id}`
   superuser endpoint or by wiping and reseeding.

**User impact.** Refresh token cookies become invalid — users must log in again. Ongoing 503
errors on logout and refresh until Redis recovers.

**Validation.** `/user/health/` shows `"redis":"ok"` and `"effective_mode":"stateful"`;
`auth_redis_circuit_breaker_open` gauge returns to 0.

**Rollback.** Not applicable — Redis loss is a data-loss event, not a config change. Focus on
recovery and re-authentication.

---

### Traefik or Docker-socket compromise

**Detection.** Unexpected containers on `m8_app_network`; traffic routed to unknown backends in
Traefik access logs; containers restarted without operator action; Docker API calls from outside
expected tooling.

**Impact.** Traefik compromise allows traffic interception or rerouting (e.g., responses
replaced, TLS terminated maliciously). Docker-socket compromise (if it were mounted) would
allow full host control. In `hardened_m8` the Docker socket is **not mounted** on the Traefik
container — the only Traefik config surface is the three read-only file mounts
(`traefik/traefik.yml`, `traefik/certs/`, `traefik/dynamic_conf.yml`).

**Containment.**
1. Immediately take the stack down: `docker compose down`.
2. Inspect the Traefik config files (`traefik.yml`, `dynamic_conf.yml`) for unauthorized changes.
3. Check `docker events` and host audit logs for unexpected Docker API calls.
4. Rotate all secrets (access key, refresh key, private-API secret, event-signing key) in case
   Traefik was used as an interception point to harvest credentials in flight.

**Rotation / Redeploy.** After confirming the config files are clean, bring the stack back up
with new secrets. If the host is suspected compromised, rebuild from the base image and redeploy.

**User impact.** Full service outage during investigation. All active sessions invalidated after
secret rotation.

**Validation.** Confirm no socket mount in `docker inspect traefik_container`. Confirm
`dynamic_conf.yml` backends match expected container-DNS names only. Run the live exposure
matrix (`security-tests-m8 run`) to confirm no routes are exposed unexpectedly.

**Rollback.** Revert `dynamic_conf.yml` to the last known-good version (tracked in git). Bring
the stack back up.

---

## Service identity and mTLS (multi-host deployments)

On a single trusted Docker host all services share `m8_app_network`; `http://` on
container-DNS names (`http://auth_user_service:8000`) is acceptable and
`ALLOW_INTERNAL_HTTP=true` is set in `auth.env.production.example` to acknowledge this.

When services run on different hosts (separate VMs, Kubernetes, Docker Swarm multi-node),
mTLS is the correct network-layer control. For the Traefik file-provider mTLS reference
configuration (CA generation, `RequireAndVerifyClientCert` TLS 1.3 internal entrypoint,
`dynamic_conf.yml` wiring, container cert mounts, migration path), see the
[auth-sdk-m8 SECURITY.md — Service identity and mTLS](https://github.com/mano8/auth-sdk-m8/blob/main/SECURITY.md#service-identity-and-mtls-multi-host-deployments).

The app-layer guards (`X-Internal-Token`, `make_internal_token_authorizer`) remain the
**primary** access control at all times; mTLS is defense-in-depth.

---

## Reporting a vulnerability

Report security issues privately to **mex.serra@gmail.com** with `[fa-auth-m8] SECURITY` in
the subject line. Do not open a public GitHub issue for vulnerabilities. Expected response
within 48 h.
