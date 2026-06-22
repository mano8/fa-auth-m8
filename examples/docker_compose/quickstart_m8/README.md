# quickstart_m8

**MariaDB 12** + **HS256** symmetric tokens + **stateful** token mode. No monitoring services — the fastest path to a running auth stack.

**Choose this when:** you want to start developing immediately without extra tooling. This is the recommended starting stack.

---

## Summary

- [Architecture](#architecture)
- [Services](#services)
- [Limitations](#limitations)
- [Setup](#setup)
- [Token mode: stateful](#token-mode-stateful)
- [URLs](#urls)
- [Port map](#port-map)
- [Configuration reference](#configuration-reference)
- [Google OAuth](#google-oauth-optional)
- [Volumes](#volumes)
- [Database isolation](#database-isolation)
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
       │
       ├──► /user/*      → auth_user_service :8000
       └──► /fastapi/*   → fastapi_full :8000
                │
       ┌────────┴────────┐
       ▼                 ▼
  m8_db (MariaDB 12)  redis_cache (Redis 8.8)
```

Traefik is the single entry point. Both services run on the internal `m8_app_network` bridge and are not reachable directly from the host.

---

## Services

| Service | Image | Accessible at |
| --- | --- | --- |
| traefik | traefik:v3.7.5 | `:8000` (HTTP), `:4430` (HTTPS), `:9000` (API), `127.0.0.1:8080` (dashboard) |
| m8_db | mariadb:12.3.2-ubi | `127.0.0.1:3306` |
| redis_cache | redis:8.8.0-alpine | `127.0.0.1:6379` |
| auth_user_service | local build | via Traefik at `/user` |
| fastapi_full | local build | via Traefik at `/fastapi` |

---

## Limitations

- **No Prometheus / Grafana.** Metrics are exposed (`METRICS_ENABLED=false` by default) but there is no scraper. Use [metrics_m8](../metrics_m8/) if you need dashboards.
- **HS256 symmetric signing.** All services share the same secret. Use [rs256_m8](../rs256_m8/) for asymmetric signing with JWKS.
- **MariaDB only.** For PostgreSQL, use [postgres_m8](../postgres_m8/).
- **No Vault.** Secrets live in the `auth.env` file. Use [vault_dev_m8](../vault_dev_m8/) for secrets-manager integration.

---

## Setup

### 1. Copy and edit the env files

```sh
cp auth.env.example auth.env
cp api.env.example api.env
```

Open `auth.env` and replace every `changethis`:

```ini
FIRST_SUPERUSER="admin@example.com"
FIRST_SUPERUSER_PASSWORD="a-strong-password"

ACCESS_SECRET_KEY="<run: python -c \"import secrets; print(secrets.token_urlsafe(64))\">"
REFRESH_SECRET_KEY="<generate same way>"

DB_USER="auth_user"
DB_PASSWORD="<generate>"
DB_ROOT_PASSWORD="<generate>"

REDIS_PASSWORD="<generate>"

PRIVATE_API_SECRET="<generate>"     # for internal service-to-service calls
SESSION_SECRET="<generate>"  # session-cookie signing key, separate from TOKENS_ENCRYPTION_KEY
TOKENS_ENCRYPTION_KEY="<generate>"  # encrypts refresh token payloads in Redis
EVENT_SIGNING_KEY="<generate>"  # HMAC key for auth event stream signing (boot fails closed without it)
```

`api.env` requires no changes for local development.

### 2. Run init

```sh
bash init.sh
```

Generates TLS certificates for Traefik. No key pair needed for HS256.

> **Windows:** `init.sh` requires bash — use **Git Bash** (included with Git for Windows) or **WSL**.

### 3. Start

```sh
docker compose up --build
```

Migrations run automatically on first boot. The superuser defined in `auth.env` is created if it does not exist.

---

## Token mode: stateful

This stack uses `TOKEN_MODE=stateful`:

| Mode | Access token validated by | Refresh token | Redis round-trip per request |
| --- | --- | --- | --- |
| `stateless` | JWT signature only | JWT signature only | No |
| `hybrid` | JWT signature only | Redis allowlist | No |
| **`stateful`** | **JWT signature + Redis blacklist** | **Redis allowlist** | **Yes** |

What happens during a session:

- **Login** → writes `rt:<jti>` to Redis (refresh allowlist) + `at:<jti>` blacklist entry, and creates a `client_session` DB row.
- **Token refresh** → atomically rotates the Redis key and updates the DB row. Reuse of an old refresh token is detected immediately.
- **Logout** → adds the access token to the Redis blacklist and deletes the refresh key. The access token is immediately invalid, regardless of its remaining lifetime.

To switch to stateless mode (no Redis required), set `TOKEN_MODE=stateless` in `auth.env`.

---

## URLs

All requests go through Traefik. Use port `9000` (HTTP) during development:

| What | URL |
| --- | --- |
| Auth API | `http://localhost:9000/user/` |
| Auth interactive docs | `http://localhost:9000/user/docs` |
| Auth ReDoc | `http://localhost:9000/user/redoc` |
| FastAPI service docs | `http://localhost:9000/fastapi/docs` |
| Health check | `http://localhost:9000/user/health/` |
| Traefik dashboard | `http://localhost:8080` |
| HTTPS | `https://localhost:4430/user/docs` (self-signed cert — accept browser warning) |

---

## Port map

| Port | Bound to | Purpose |
| --- | --- | --- |
| `8000` | `0.0.0.0` | Traefik HTTP |
| `4430` | `0.0.0.0` | Traefik HTTPS |
| `9000` | `127.0.0.1` | API services entry (set `API_BIND_IP` in `auth.env` to expose on LAN) |
| `8080` | `127.0.0.1` | Traefik dashboard |
| `3306` | `127.0.0.1` | MariaDB (use with any MySQL-compatible DB client) |
| `6379` | `127.0.0.1` | Redis |

---

## Configuration reference

### `auth.env` — auth service

| Variable | Default | Notes |
| --- | --- | --- |
| `TOKEN_MODE` | `stateful` | `stateless` / `hybrid` / `stateful` |
| `ACCESS_TOKEN_ALGORITHM` | `HS256` | `HS256` for symmetric signing |
| `ACCESS_SECRET_KEY` | — | HMAC secret (HS256 only) |
| `REFRESH_SECRET_KEY` | — | HMAC secret for refresh tokens |
| `SELECTED_DB` | `Mysql` | `Mysql` or `Postgres` |
| `DB_HOST` | `m8_db` | Docker service name — do not change for compose |
| `FRONTEND_HOST` | `http://localhost:5173` | Added to CORS allowed origins |
| `API_PREFIX` | `/user` | URL prefix for all auth routes |
| `PRIVATE_API_SECRET` | — | Secret for `X-Internal-Token` header |
| `SESSION_SECRET` | — | Signing key for the session cookie (distinct from `TOKENS_ENCRYPTION_KEY`) |
| `TOKENS_ENCRYPTION_KEY` | — | Fernet key for encrypting refresh token payloads in Redis |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_MINUTES` | `3600` | Refresh token lifetime (60 h) |
| `LOGIN_RATE_LIMIT_REQUESTS` | `5` | Max login attempts per window per email |
| `LOGIN_RATE_LIMIT_WINDOW_MINUTES` | `15` | Login rate-limit window in minutes |
| `REFRESH_RATE_LIMIT_REQUESTS` | `10` | Max refresh rotations per window per user |
| `REFRESH_RATE_LIMIT_WINDOW_MINUTES` | `5` | Refresh rate-limit window in minutes |
| `TRUSTED_PROXY_COUNT` | `1` | Trusted reverse-proxy hops in front. Used to extract real client IP from `X-Forwarded-For`. Set to `0` if no proxy. |
| `METRICS_ENABLED` | `false` | Set to `true` to expose `/user/metrics` |
| `AUTH_SERVICE_ROLE` | `issuer` | This service signs tokens |
| `TOKEN_ISSUER` | `https://auth.example.com` | `iss` claim; must be identical in every consumer. Required when `TOKEN_STRICT_VALIDATION=true` |
| `TOKEN_AUDIENCE` | `https://api.example.com` | `aud` claim; must be identical in every consumer. Required when `TOKEN_STRICT_VALIDATION=true` |
| `TOKEN_STRICT_VALIDATION` | `true` | Secure-by-default: enforces an exact `iss`/`aud` match and **boot fails closed** unless both are set. Set `false` only for single-service/local dev |
| `EVENT_SIGNING_ENABLED` | `true` | Secure-by-default: HMAC-signs auth-event payloads (SSE bridge). **Boot fails closed** unless `EVENT_SIGNING_KEY` is set. Set `false` to disable |
| `EVENT_SIGNING_KEY` | — | Shared HMAC secret for event signing; required when `EVENT_SIGNING_ENABLED=true` |
| `EVENT_STREAM_ENABLED` | `true` | Master switch for the SSE bridge (`GET /private/v1/events/stream`). Set `false` to disable the endpoint fleet-wide |
| `EVENT_STREAM_BUFFER_SIZE` | `256` | Ring-buffer depth for `Last-Event-ID` resume |
| `EVENT_STREAM_HEARTBEAT_SECONDS` | `15` | Heartbeat comment-frame interval — keep below the consumer read timeout and any reverse-proxy idle timeout |
| `EVENT_STREAM_MAX_QUEUE` | `64` | Per-connection outbound queue depth before a slow consumer is disconnected (it reconnects and resumes/flushes) |

### `api.env` — consumer service

| Variable | Notes |
| --- | --- |
| `AUTH_SERVICE_ROLE` | `consumer` — verifies tokens, does not sign them |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Should match auth service value |
| `REVOCATION_CACHE_TTL_SECONDS` | `30` — seconds to cache positive JTI-validation results; event stream evicts early. Set `0` to disable caching (default) |

---

## Google OAuth (optional)

Uncomment and fill in `auth.env`:

```ini
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"
```

Redis is required for the OAuth code-exchange callback. This stack includes Redis, so OAuth works out of the box once credentials are set.

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
| `./db_data` | Persistent MariaDB data |
| `./redis/redis_data` | Persistent Redis snapshots |
| `./shared_migrations` | Alembic migration files (auto-created, shared between services) |
| `../../../auth_user_service` | Live source mount — Python changes apply without rebuild |

---

## Database isolation

This stack defaults to **Scenario 2** (per-service isolation): `auth_db` and `api_db` are created as separate databases with separate users on first volume init. To switch to a single shared DB or add more services, see the scenario blocks in `auth.env.example` and the [database isolation guide](../README.md#database-isolation).

Database provisioning runs **once** on first volume creation. If DB config changes after the volume exists, reset with `bash init.sh --reset-db`.

---

## Common operations

```sh
# Start in background
docker compose up -d --build

# Follow logs for all services
docker compose logs -f

# Follow logs for one service
docker compose logs -f auth_user_service

# Inspect Redis keyspace after a login
docker compose exec redis_cache redis-cli -a "$REDIS_PASSWORD" INFO keyspace

# Stop (keeps volumes and data)
docker compose stop

# Stop and remove containers (keeps data volumes)
docker compose down

# Full reset — stops containers and wipes the database (prompts for confirmation)
bash init.sh --reset-db

# Rebuild one service after dependency changes
docker compose up -d --build auth_user_service
```

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

---

## Troubleshooting

**Services fail to start immediately** — `auth_user_service` waits for MariaDB to pass its health check (MariaDB can take 20–30 s on first boot), then `fastapi_full` waits for `auth_user_service` to pass its own health check. Watch the logs with `docker compose logs -f`.

**`changethis` rejection on startup** — the service refuses to start if placeholder secrets are detected. Replace all `changethis` values in `auth.env`.

**Port conflict** — if `3306`, `6379`, or `9000` are already in use, find the process with `netstat -ano | findstr 3306` (Windows) or `lsof -i :3306` (Mac/Linux).

**Database connection refused** — keep `DB_HOST=m8_db` in `auth.env`. Services reach the database over the internal Docker network using the service name, not `localhost`.

---

> [Docker Compose examples](../README.md) · [Repository root](https://github.com/mano8/fa-auth-m8/tree/main)
