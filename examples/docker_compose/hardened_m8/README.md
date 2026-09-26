# hardened_m8

**PostgreSQL 18** + **RS256 asymmetric token signing** + **stateful** token mode + **Prometheus & Grafana** observability + **container hardening** + **network segmentation**.

`auth_user_service` runs from the published Docker Hub image (`tepochtli/fa-auth-m8:2.2.3`). Secrets live in env files — no Vault required.

**Choose this when:** you want production-grade container posture (read-only rootfs, dropped capabilities, resource limits) and observability, but don't need HashiCorp Vault. Use [vault_dev_m8](../vault_dev_m8/) when you also need secrets-manager injection.

---

## Summary

- [Architecture](#architecture)
- [Hardening baseline](#hardening-baseline)
- [Services](#services)
- [Setup](#setup)
- [Token mode: stateful](#token-mode-stateful)
- [Observability](#observability)
- [URLs](#urls)
- [Port map](#port-map)
- [Configuration reference](#configuration-reference)
- [Key rotation](#key-rotation)
- [Volumes](#volumes)
- [Common operations](#common-operations)
- [Live testing](#live-testing)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```text
Browser / Frontend
       │
       ▼
  Traefik :9000
       │ (app_net)
       ├──► /user/*      → auth_user_service :8000  (RS256 issuer)
       └──► /fastapi/*   → fastapi_full :8000    (RS256 consumer via JWKS)

  app_net ─── Traefik + auth + fastapi + Prometheus + Grafana
  data_net ── m8_db (PostgreSQL 18) + redis_cache (Redis 8.8)  [internal: true]

  Auth and fastapi services sit on both networks.
  Traefik sits on app_net only — cannot reach DB or Redis directly.
```

### Network segmentation

Two Docker networks isolate external-facing traffic from the data tier:

| Network | Services | internet gateway |
| --- | --- | --- |
| `app_net` | traefik, auth, fastapi, prometheus, grafana | yes |
| `data_net` | m8_db, redis_cache, auth, fastapi | **no** (`internal: true`) |

`data_net` has no gateway — containers on it cannot initiate outbound internet connections, and Traefik (on `app_net` only) cannot reach the database or Redis directly.

---

## Hardening baseline

Applied to `auth_user_service` and `fastapi_full`:

| Option | Value | Effect |
| --- | --- | --- |
| `security_opt` | `no-new-privileges:true` | Blocks privilege escalation via setuid/setgid |
| `cap_drop` | `ALL` | Removes all Linux capabilities |
| `read_only` | `true` | Root filesystem is read-only |
| `tmpfs` | `/tmp`, `/run` | Writable in-memory mounts for temp files |
| `PYTHONDONTWRITEBYTECODE` | `1` | Prevents Python writing `.pyc` to read-only paths |
| `deploy.resources.limits` | `1 CPU`, `512 MB` | Prevents resource exhaustion |

Traefik posture:

| Option | Value | Effect |
| --- | --- | --- |
| Routing provider | file only (`traefik/dynamic_conf.yml`) | No Docker provider, so `/var/run/docker.sock` is never mounted — the Docker API is equivalent to host root |
| Backend discovery | Docker DNS by container name | Routers/services are declared statically; backends resolve as `http://auth_user_service:8000` over `app_net` |

Auth degradation settings in `auth.env`:

| Setting | Value | Effect |
| --- | --- | --- |
| `AUTH_STRICT_MODE` | `true` | Overrides all per-control modes to `fail_closed` |
| `RATE_LIMIT_FAILURE_MODE` | `fail_closed` | Redis outage → 503, not open |
| `ACCESS_REVOCATION_FAILURE_MODE` | `fail_closed` | Redis outage → tokens not accepted |

### Redis ACLs (least privilege)

The `redis_cache` bootstrap provisions a **scoped per-service** ACL instead of the
old open `appuser ~* +@all`:

| User | Key access | Commands |
| --- | --- | --- |
| `auth` (the app, via `REDIS_USER=auth`) | only its own prefixes — `oauth_session:*`, `auth_code:*`, `login:*`, `refresh:*`, `exchange:*`, `rt:*`, `jwt:blacklist:*`, `rate:*`, `api_key:*` | `+@read +@write +@transaction +@connection +eval -@dangerous` — exactly the commands the service uses (string/hash ops, pipelined transactions, the refresh-rotation Lua `EVAL`); admin/dangerous denied |
| `default` | none (`resetkeys`) | `-@all +@connection -@dangerous` — connection commands only, so the healthcheck `PING` still works; no data or admin access |

A leaked auth Redis credential can therefore only touch the auth service's own
keyspace, and the always-present `default` user can no longer read, write, or
flush data. The contract is locked by `tests/security/test_redis_acl_policy.py`.

---

## Services

| Service | Image | Accessible at |
| --- | --- | --- |
| traefik | traefik:v3.7.5 | `:8000` (HTTP), `:4430` (HTTPS), `:9000` (API), `127.0.0.1:8080` (dashboard) |
| m8_db | postgres:18.4-alpine | `127.0.0.1:5432` |
| redis_cache | redis:8.8.0-alpine | `127.0.0.1:6379` |
| prometheus | ubuntu/prometheus:3.11-26.04_stable | `127.0.0.1:9090` |
| grafana | grafana/grafana:13.1.0 | `127.0.0.1:3000` |
| auth_user_service | [tepochtli/fa-auth-m8:2.2.3](https://hub.docker.com/r/tepochtli/fa-auth-m8) | via Traefik at `/user` |
| fastapi_full | local build | via Traefik at `/fastapi` |

---

## Setup

### 1. Copy and edit the env files

```sh
cp .env.example .env
cp auth.env.example auth.env
cp api.env.example api.env
```

Open `.env` and replace every `changethis`:

```ini
DB_PASSWORD=<strong-postgres-root-password>
AUTH_DB_PASSWORD=<strong-auth-db-password>
API_DB_PASSWORD=<strong-api-db-password>
REDIS_PASSWORD=<strong-redis-password>
```

Open `auth.env` and replace every `changethis`:

```ini
DB_USER=<same-as-AUTH_DB_USER-in-.env>
DB_PASSWORD=<same-as-AUTH_DB_PASSWORD-in-.env>
REDIS_PASSWORD=<same-as-REDIS_PASSWORD-in-.env>
REFRESH_SECRET_KEY=<64-char-random>
PRIVATE_API_SECRET=<64-char-random>
SESSION_SECRET=<64-char-random>  # session-cookie signing key, separate from TOKENS_ENCRYPTION_KEY
TOKENS_ENCRYPTION_KEY=<64-char-random>
EVENT_SIGNING_KEY=<64-char-random>  # HMAC key for auth event stream signing (boot fails closed without it)
FIRST_SUPERUSER=admin@example.com
FIRST_SUPERUSER_PASSWORD=<strong-password>
```

Open `api.env` and replace every `changethis`:

```ini
DB_USER=<same-as-API_DB_USER-in-.env>
DB_PASSWORD=<same-as-API_DB_PASSWORD-in-.env>
REDIS_PASSWORD=<same-as-REDIS_PASSWORD-in-.env>
REFRESH_SECRET_KEY=<64-char-random>
```

`ACCESS_KEY_ID` in `auth.env` can stay as `changethis_hex_kid` — `init.sh` derives and writes the correct fingerprint automatically.

### 2. Generate RSA key pair + TLS certificates

```sh
bash init.sh
```

> **Windows:** use **Git Bash** or **WSL**.

Re-running `bash init.sh` on a stack that already has a keypair does not
regenerate it — but it does re-derive `kid` from the mounted `keys/public.pem`
and compares it against `ACCESS_KEY_ID`. A match is confirmed and left alone;
an unset or stale value is re-bound with a `NOTE:` naming the correction. Use
`--rotate-keys` (below) to actually generate a new keypair.

### 3. Start

```sh
docker compose up -d
```

`auth_user_service` pulls from Docker Hub — no `--build` needed for it. Only `fastapi_full` is built locally.

> **Pinned for production:** the image is pinned to a specific release tag
> (`tepochtli/fa-auth-m8:2.2.3`) in `docker-compose.yml` for reproducible deployments —
> bump it to a newer published tag as releases are cut (never use `:latest`).

---

## Token mode: stateful

| Mode | Access token validated by | Refresh token | Redis round-trip per request |
| --- | --- | --- | --- |
| `stateless` | JWT signature only | JWT signature only | No |
| `hybrid` | JWT signature only | Redis allowlist | No |
| **`stateful`** | **JWT signature + Redis blacklist** | **Redis allowlist** | **Yes** |

With `AUTH_STRICT_MODE=true` and `ACCESS_REVOCATION_FAILURE_MODE=fail_closed`, a Redis outage causes authenticated requests to return **503** rather than bypassing revocation checks. This is the deliberately conservative posture for this stack.

---

## Observability

### Grafana — `http://localhost:3000`

Pre-provisioned with a Prometheus datasource. Default credentials: `admin` / `foobar`
(change on first login via `grafana/config.monitoring`).

### Prometheus — `http://localhost:9090`

Scrapes `auth_user_service` at `/user/metrics` and `fastapi_full` at `/fastapi/metrics`.
Alert rules in `prometheus/alerts.yml` cover API key rate-limit ratios and flush latency.

---

## URLs

| What | URL |
| --- | --- |
| Auth API | `http://localhost:9000/user/` |
| Auth interactive docs | `http://localhost:9000/user/docs` |
| JWKS endpoint | `http://localhost:9000/user/.well-known/jwks.json` |
| FastAPI service docs | `http://localhost:9000/fastapi/docs` |
| Health check | `http://localhost:9000/user/health/` |
| Traefik dashboard | `http://localhost:8080` |
| Prometheus | `http://localhost:9090` |
| Grafana | `http://localhost:3000` |
| HTTPS | `https://localhost:4430/user/docs` (self-signed cert — accept browser warning) |

---

## Port map

| Port | Bound to | Purpose |
| --- | --- | --- |
| `8000` | `0.0.0.0` | Traefik HTTP |
| `4430` | `0.0.0.0` | Traefik HTTPS |
| `9000` | `127.0.0.1` | API services entry (set `API_BIND_IP` in `.env` to expose on LAN) |
| `8080` | `127.0.0.1` | Traefik dashboard |
| `5432` | `127.0.0.1` | PostgreSQL |
| `6379` | `127.0.0.1` | Redis |
| `9090` | `127.0.0.1` | Prometheus |
| `3000` | `127.0.0.1` | Grafana |

---

## Configuration reference

### `.env` — shared infrastructure

| Variable | Default | Notes |
| --- | --- | --- |
| `API_BIND_IP` | `127.0.0.1` | Set to `0.0.0.0` to expose port 9000 on LAN |
| `DB_USER` | `m8_admin` | PostgreSQL superuser for bootstrap only |
| `DB_PASSWORD` | — | PostgreSQL superuser password |
| `DB_PORT` | `5432` | PostgreSQL port |
| `AUTH_DB_USER` / `AUTH_DB_PASSWORD` / `AUTH_DB_NAME` | — | Per-service isolation (Scenario 2) |
| `API_DB_USER` / `API_DB_PASSWORD` / `API_DB_NAME` | — | Per-service isolation (Scenario 2) |
| `REDIS_PASSWORD` | — | Redis password |

### `auth.env` — auth service (issuer)

| Variable | Default | Notes |
| --- | --- | --- |
| `ACCESS_TOKEN_ALGORITHM` | `RS256` | Asymmetric signing |
| `REFRESH_TOKEN_ALGORITHM` | `HS256` | Refresh tokens remain symmetric |
| `ACCESS_PRIVATE_KEY_FILE` | `/opt/keys/private.pem` | Path inside the container |
| `ACCESS_PUBLIC_KEY_FILE` | `/opt/keys/public.pem` | Path inside the container |
| `ACCESS_KEY_ID` | — | Stable `kid` written by `init.sh` |
| `TOKEN_MODE` | `stateful` | `stateless` / `hybrid` / `stateful` |
| `AUTH_STRICT_MODE` | `true` | Overrides all failure modes to `fail_closed` |
| `RATE_LIMIT_FAILURE_MODE` | `fail_closed` | Redis outage → 503 on rate-limited endpoints |
| `ACCESS_REVOCATION_FAILURE_MODE` | `fail_closed` | Redis outage → tokens not accepted |
| `TRUSTED_PROXY_COUNT` | `1` | Trusted proxy hops for real client IP extraction. Set to `0` if no proxy. |
| `METRICS_ENABLED` | `true` | Exposes `/user/metrics` for Prometheus |
| `TOKEN_ISSUER` | `https://auth.example.com` | `iss` claim; must be identical in every consumer. Required when `TOKEN_STRICT_VALIDATION=true` |
| `TOKEN_AUDIENCE` | `https://api.example.com` | `aud` claim; must be identical in every consumer. Required when `TOKEN_STRICT_VALIDATION=true` |
| `TOKEN_STRICT_VALIDATION` | `true` | Secure-by-default: enforces an exact `iss`/`aud` match and **boot fails closed** unless both are set |
| `EVENT_SIGNING_ENABLED` | `true` | Secure-by-default: HMAC-signs auth-event payloads (SSE bridge). **Boot fails closed** unless `EVENT_SIGNING_KEY` is set |
| `EVENT_SIGNING_KEY` | — | Shared HMAC secret for event signing; required when `EVENT_SIGNING_ENABLED=true` |
| `EVENT_STREAM_ENABLED` | `true` | Master switch for the SSE bridge (`GET /private/v1/events/stream`). Set `false` to disable the endpoint fleet-wide |
| `EVENT_STREAM_BUFFER_SIZE` | `256` | Ring-buffer depth for `Last-Event-ID` resume |
| `EVENT_STREAM_HEARTBEAT_SECONDS` | `15` | Heartbeat comment-frame interval — keep below the consumer read timeout and any reverse-proxy idle timeout |
| `EVENT_STREAM_MAX_QUEUE` | `64` | Per-connection outbound queue depth before a slow consumer is disconnected (it reconnects and resumes/flushes) |

### `api.env` — consumer service

| Variable | Notes |
| --- | --- |
| `AUTH_SERVICE_ROLE` | `consumer` — verifies tokens via JWKS, does not sign them |
| `JWKS_URI` | `http://auth_user_service:8000/user/.well-known/jwks.json` |
| `JWKS_CACHE_TTL_SECONDS` | `300` — how long to cache the public key before re-fetching |
| `REVOCATION_CACHE_TTL_SECONDS` | `30` — seconds to cache positive JTI-validation results; event stream evicts early. Set `0` to disable caching (default) |

---

## Key rotation

```sh
# 1. Regenerate the RSA key pair. The previous public key is retained as
#    keys/public_old.pem and ACCESS_KEY_ID / ACCESS_KEY_ID_OLD are both written
#    into auth.env, so neither kid can drift from the key it labels.
bash init.sh --rotate-keys

# 2. Restart the auth service (picks up new private key + kid)
docker compose up -d auth_user_service

# 3. Consumers self-update — no restart needed

# 4. Once every old-key access token has expired, close the overlap window:
#    unset ACCESS_PUBLIC_KEY_OLD_FILE + ACCESS_KEY_ID_OLD in auth.env, redeploy
#    auth, and delete keys/public_old.pem
```

JWKS now publishes **both** keys, so access tokens issued before the rotation keep verifying with no
consumer restart and no gap. Close the overlap window once every old-key token has expired
(`ACCESS_TOKEN_EXPIRE_MINUTES` + the consumers' `JWKS_CACHE_TTL_SECONDS`): unset
`ACCESS_PUBLIC_KEY_OLD_FILE` and `ACCESS_KEY_ID_OLD`, redeploy auth, and delete `keys/public_old.pem`.

Since `2.1.0` an `ACCESS_KEY_ID` that is not the DER fingerprint of the key it labels is a **startup
failure** — see [SECURITY.md](../SECURITY.md#rs256es256-signing-keypair--access_key_id).

---

## Google OAuth (optional)

Uncomment and fill in `auth.env`:

```ini
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"
```

Redis is required for the OAuth code-exchange callback. This stack includes Redis, so OAuth works once credentials are set.

For Chrome extension or native-app flows (PKCE), also uncomment the optional block in `auth.env`:

```ini
GOOGLE_OAUTH_REDIRECT_URI=https://yourdomain.com/user/google-auth/oauth-callback/
OAUTH_ALLOWED_REDIRECT_SCHEMES=chrome-extension://
# OAUTH_ALLOWED_REDIRECT_PREFIXES=chrome-extension://your-extension-id.../
CORS_ALLOWED_ORIGIN_SCHEMES=chrome-extension://
```

---

## Volumes

| Path | Purpose |
| --- | --- |
| `./keys` | RSA key pair (mounted read-only into auth container) |
| `./db_data` | Persistent PostgreSQL data |
| `./redis/redis_data` | Persistent Redis snapshots |
| `./prometheus/data` | Prometheus TSDB |
| `./grafana/data` | Grafana dashboards and state |
| `./shared_migrations` | Alembic migration files (auto-created, shared between services) |

---

## Common operations

```sh
# Start in background
docker compose up -d

# Follow logs for all services
docker compose logs -f

# Follow logs for auth service
docker compose logs -f auth_user_service

# Verify JWKS endpoint
curl http://localhost:9000/user/.well-known/jwks.json | python -m json.tool

# Full reset — stops containers and wipes the database
bash init.sh --reset-db
```

`--reset-db` removes `db_data/` even when the database container owns it as its
own uid — it falls back to a throwaway root container, so no manual `sudo rm` is
needed on WSL2/Linux bind mounts. `init.sh` also enforces `chmod 600` on runtime
`*.env` files and private keys on every run.

---

## Live testing

Validate this stack's security posture with the [`security-tests-m8`](https://github.com/mano8/security-tests-m8) live suite (requires the stack to be up). It attacks the running stack — auth bypass, token forgery, JWKS/algorithm confusion, privilege escalation, OWASP API risks — flaws that only surface against a live deployment:

```sh
pip install --upgrade security-tests-m8

cp test.env.example test.env
# Edit test.env: set LIVE_TEST_ADMIN_EMAIL / LIVE_TEST_ADMIN_PASSWORD to a
# DEDICATED test-only superuser (must already exist; never FIRST_SUPERUSER).

security-tests-m8 preflight --deployment-root .
security-tests-m8 run --env-file test.env
```

The suite auto-skips checks that don't apply to this stack. Delete or disable the dedicated test superuser when you're done — the suite does not remove it. See [shared_live_tests/](../shared_live_tests/) for the full rationale (why a dedicated superuser, when to run, cleanup) and the advanced pytest mode.

Manual smoke test:

```sh
curl http://localhost:9000/user/health/
# Expected: {"status":"ok","token_mode":"stateful","redis":"ok","database":"ok",...}
```

---

## Production deployment

When deploying publicly, replace `traefik/dynamic_conf.yml` with `traefik/production_dynamic_conf.yml`. The production config:

- Ships `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Strict-Transport-Security` (HSTS) **commented out** in `security-headers-prod` — both are opt-in. Uncomment only after TLS is stable with a trusted certificate (and confirm the CSP does not break your frontend/docs). HSTS stays off by default because, once sent, browsers refuse plain HTTP to the host for the full `stsSeconds` even after you disable it.
- Dev `dynamic_conf.yml` has no CSP so Swagger UI works during development.

Also update the `Host` rules in the production config to match your actual FQDN.

**Socketless by design.** The production path — whether you apply `docker-compose.production.yml` or copy `production_dynamic_conf.yml` over `dynamic_conf.yml` — never mounts `/var/run/docker.sock`. Traefik routes via the **file provider only** (`traefik.yml` declares no `docker` provider); backends are declared statically and resolve over Docker DNS by container name (`http://auth_user_service:8000`), so no socket mount and no per-container `traefik.*` discovery labels are needed. Mounting the socket — even read-only — grants the Docker API, which is equivalent to host root. This contract is locked by `tests/security/test_socketless_traefik.py`.

---

## Troubleshooting

**Auth service fails to start — key file not found** — ensure you ran `bash init.sh` and that `keys/private.pem` and `keys/public.pem` both exist.

**JWKS endpoint returns empty `keys` array** — the service started before the key files were mounted. Restart: `docker compose restart auth_user_service`.

**Services fail to start immediately** — `auth_user_service` waits for PostgreSQL (`pg_isready`). PostgreSQL typically initialises in 10–20 s on first boot. `fastapi_full` then waits for `auth_user_service` to pass its own health check. Watch the logs with `docker compose logs -f`.

**`changethis` rejection on startup** — replace all `changethis` values in `.env`, `auth.env`, and `api.env`.

**Grafana shows no data** — confirm `METRICS_ENABLED=true` in `auth.env`, then make at least one request to generate metrics. Check Prometheus targets at `http://localhost:9090/targets`.

**Port conflict** — identify the conflicting process with `netstat -ano | findstr <PORT>` (Windows) or `lsof -i :<PORT>` (Mac/Linux).

---

> [Docker Compose examples](../README.md) · [Repository root](https://github.com/mano8/fa-auth-m8/tree/main)

<!-- env-files:start -->
## Environment files

Copy each template to the name after the arrow (`init.sh` does this where the stack has one), then replace every
`changethis`. Every key is documented in its template; each secret carries a `# Value:` line with its minimum
and maximum length and allowed characters. Real env files are gitignored and never committed.

| Template → file | Read by | Must be set (placeholders) |
| --- | --- | --- |
| `.env.example` → `.env` | Compose itself (`${VAR}` interpolation) and the engine init scripts | `DB_PASSWORD`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD`, `API_DB_USER`, `API_DB_PASSWORD`, `REDIS_PASSWORD` |
| `.env.production.example` → `.env.production` | Compose itself (`${VAR}` interpolation) and the engine init scripts | `DB_PASSWORD`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD`, `API_DB_USER`, `API_DB_PASSWORD`, `REDIS_PASSWORD` |
| `api.env.example` → `api.env` | `fastapi_full` | `DB_USER`, `DB_PASSWORD`, `REFRESH_SECRET_KEY`, `PRIVATE_API_SECRET`, `EVENT_SIGNING_KEY` |
| `api.env.production.example` → `api.env.production` | `fastapi_full` (via `docker-compose.production.yml`) | `DB_USER`, `DB_PASSWORD`, `REFRESH_SECRET_KEY`, `PRIVATE_API_SECRET`, `EVENT_SIGNING_KEY` |
| `auth.env.example` → `auth.env` | `auth_user_service` | `DB_USER`, `DB_PASSWORD`, `REDIS_PASSWORD`, `ACCESS_KEY_ID`, `REFRESH_SECRET_KEY`, `FIRST_SUPERUSER_PASSWORD`, `PRIVATE_API_SECRET`, `SESSION_SECRET`, `TOKENS_ENCRYPTION_KEY`, `EVENT_SIGNING_KEY` |
| `auth.env.production.example` → `auth.env.production` | `auth_user_service` (via `docker-compose.production.yml`) | `DB_USER`, `DB_PASSWORD`, `REDIS_PASSWORD`, `ACCESS_KEY_ID`, `REFRESH_SECRET_KEY`, `FIRST_SUPERUSER_PASSWORD`, `PRIVATE_API_SECRET`, `SESSION_SECRET`, `TOKENS_ENCRYPTION_KEY`, `EVENT_SIGNING_KEY` |
| `grafana.env.example` → `grafana.env` | `grafana` | `GF_SECURITY_ADMIN_PASSWORD` |
| `test.env.example` → `test.env` | the live security tests (`shared_live_tests`), not a container | `LIVE_TEST_ADMIN_EMAIL`, `LIVE_TEST_ADMIN_PASSWORD`, `LIVE_TEST_PRIVATE_API_SECRET`, `LIVE_TEST_REFRESH_SECRET_KEY` |

Generate a value that satisfies every secret rule (48 chars: upper, lower, digit and `-`):

```sh
python -c "import secrets,string; a=string.ascii_letters+string.digits; print('Aa1-'+''.join(secrets.choice(a) for _ in range(44)))"
```

Values must avoid spaces, `$`, `#`, quotes and backslashes: Compose interpolates `$`, dotenv treats `#` as a
comment, and several values are embedded in URLs, JSON or the Redis ACL.
<!-- env-files:end -->
