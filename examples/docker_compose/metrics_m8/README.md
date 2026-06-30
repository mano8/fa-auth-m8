# metrics_m8

**PostgreSQL 18** + **HS256** symmetric tokens + **stateful** token mode + **Prometheus & Grafana** observability. Designed for validating the complete stateful auth flow and exploring metrics.

**Choose this when:** you want to watch what happens in Redis and the database during login/logout cycles, or need to develop against a metrics dashboard.

---

## Summary

- [Architecture](#architecture)
- [Services](#services)
- [Setup](#setup)
- [Token mode: stateful](#token-mode-stateful)
- [Observability](#observability)
- [URLs](#urls)
- [Port map](#port-map)
- [Configuration reference](#configuration-reference)
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
  m8_db (PostgreSQL 18)  redis_cache (Redis 8.8)
                         │
                   (access token blacklist
                    + refresh token store)

  Prometheus :9090  ←── scrapes /user/metrics
       │
  Grafana :3000
```

---

## Services

| Service | Image | Accessible at |
| --- | --- | --- |
| traefik | traefik:v3.7.5 | `:8000` (HTTP), `:4430` (HTTPS), `:9000` (API), `127.0.0.1:8080` (dashboard) |
| m8_db | postgres:18.4-alpine | `127.0.0.1:5432` |
| redis_cache | redis:8.8.0-alpine | `127.0.0.1:6379` |
| prometheus | ubuntu/prometheus:3.11-26.04_stable | `127.0.0.1:9090` |
| grafana | grafana/grafana:13.1.0-25530058790 | `127.0.0.1:3000` |
| auth_user_service | local build | via Traefik at `/user` |
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
# PostgreSQL superuser (used for container bootstrap and init-db.sh)
DB_USER="changethis_admin"
DB_PASSWORD="<generate>"
DB_PORT=5432

AUTH_DB_USER="auth_user"
AUTH_DB_PASSWORD="<generate>"
API_DB_USER="api_user"
API_DB_PASSWORD="<generate>"

REDIS_PASSWORD="<generate>"
```

Open `auth.env` and replace:

```ini
PRIVATE_API_SECRET="<generate>"     # for internal service-to-service calls
SESSION_SECRET="<generate>"  # session-cookie signing key, separate from TOKENS_ENCRYPTION_KEY
TOKENS_ENCRYPTION_KEY="<generate>"  # encrypts refresh token payloads at rest
EVENT_SIGNING_KEY="<generate>"  # HMAC key for auth event stream signing (boot fails closed without it)
```

`api.env` requires no changes for local development.

### 2. Run init

```sh
bash init.sh
```

Generates TLS certificates for Traefik. No keys needed for HS256.

### 3. Start

```sh
docker compose up --build
```

Migrations run automatically on first boot. The superuser defined in `.env` is created
if it does not exist.

---

## Token mode: stateful

This stack defaults to `TOKEN_MODE=stateful`:

| Mode | Access token validated by | Refresh token | Redis round-trip per request |
| --- | --- | --- | --- |
| `stateless` | JWT signature only | JWT signature only | No |
| `hybrid` | JWT signature only | Redis allowlist | No |
| **`stateful`** | **JWT signature + Redis blacklist** | **Redis allowlist** | **Yes** |

What happens in Redis and the database during a full session:

- **Login** → writes `rt:<jti>` to Redis (refresh allowlist) and creates a `client_session`
  DB row.
- **Token refresh** → atomically rotates `rt:<old_jti>` → `rt:<new_jti>` in Redis and
  updates the DB row. Reuse of an old refresh token is detected immediately.
- **Logout** → deletes `rt:<jti>`, writes `jwt:blacklist:<jti>` with a TTL matching the
  access token's remaining lifetime, and removes the DB session row.
- **Request validation** → checks `jwt:blacklist:<jti>` on every authenticated request.

After a full login → logout cycle, the blacklist key expires automatically via its TTL
and Redis returns to an empty keyspace.

Verify writes after a login:

```sh
docker compose exec redis_cache redis-cli -a "$REDIS_PASSWORD" INFO keyspace
# Expected: db0:keys=1,expires=1,...
```

---

## Observability

### Grafana — `http://localhost:3000`

Pre-provisioned with a Prometheus datasource. Default credentials: `admin` / `admin`
(change on first login).

Dashboard config lives in `./grafana/provisioning/`. Add your own dashboards by dropping
JSON files into the `dashboards/` subdirectory.

### Prometheus — `http://localhost:9090`

Scrapes metrics from `auth_user_service` at `/user/metrics` (enabled by `METRICS_ENABLED=true`
in `auth.env`). Use the Prometheus expression browser to query request counts, latency
histograms, and Redis operation rates.

Useful queries to start with:

```promql
# HTTP request rate by endpoint
rate(http_requests_total[1m])

# 95th percentile response time
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

---

## URLs

| What | URL |
| --- | --- |
| Auth API | `http://localhost:9000/user/` |
| Auth interactive docs | `http://localhost:9000/user/docs` |
| Auth ReDoc | `http://localhost:9000/user/redoc` |
| FastAPI service docs | `http://localhost:9000/fastapi/docs` |
| Traefik dashboard | `http://localhost:8080` |
| Prometheus | `http://localhost:9090` |
| Grafana | `http://localhost:3000` |
| HTTPS | `https://localhost:4430/user/docs` (self-signed cert — accept browser warning) |

---

## Port map

| Port | Bound to | Purpose |
| --- | --- | --- |
| `8000` | `0.0.0.0` | Traefik HTTP |
| `4430` | `0.0.0.0` | Traefik HTTPS — published on all interfaces, but the `/user` and `/fastapi` routers are `Host(`localhost`)`-gated, so non-localhost requests get `404` by default. To serve them on the LAN, drop the `Host(`localhost`)` prefix in `traefik/dynamic_conf.yml` (see the router comments). |
| `9000` | `127.0.0.1` | API services entry (set `API_BIND_IP` in `.env` to expose on LAN) |
| `8080` | `127.0.0.1` | Traefik dashboard |
| `5432` | `127.0.0.1` | PostgreSQL |
| `6379` | `127.0.0.1` | Redis |
| `9090` | `127.0.0.1` | Prometheus |
| `3000` | `127.0.0.1` | Grafana |

---

## Configuration reference

### `.env` — shared across all services

| Variable | Default | Notes |
| --- | --- | --- |
| `TOKEN_MODE` | `stateful` | `stateless` / `hybrid` / `stateful` |
| `ACCESS_TOKEN_ALGORITHM` | `HS256` | `HS256` for symmetric, `RS256` for asymmetric |
| `ACCESS_SECRET_KEY` | — | HMAC secret (HS256 only) |
| `REFRESH_SECRET_KEY` | — | HMAC secret for refresh tokens |
| `SELECTED_DB` | `Postgres` | `Mysql` or `Postgres` |
| `DB_HOST` | `m8_db` | Docker service name — do not change for compose |
| `FRONTEND_HOST` | `http://localhost:5173` | Added to CORS allowed origins |
| `AUTH_PREFIX` | `/user` | Path prefix consumers use to reach auth |

### `auth.env` — auth service only

| Variable | Notes |
| --- | --- |
| `PRIVATE_API_SECRET` | Secret for `X-Internal-Token` header (service-to-service calls) |
| `SESSION_SECRET` | Signing key for the session cookie (distinct from `TOKENS_ENCRYPTION_KEY`) |
| `TOKENS_ENCRYPTION_KEY` | Fernet key for encrypting refresh token payloads in Redis |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Default: 60 min |
| `REFRESH_TOKEN_EXPIRE_MINUTES` | Default: 3600 min (60 h) |
| `LOGIN_RATE_LIMIT_REQUESTS` | Default: 5 — max login attempts per window per email |
| `LOGIN_RATE_LIMIT_WINDOW_MINUTES` | Default: 15 — login rate-limit window in minutes |
| `REFRESH_RATE_LIMIT_REQUESTS` | Default: 10 — max refresh rotations per window per user |
| `REFRESH_RATE_LIMIT_WINDOW_MINUTES` | Default: 5 — refresh rate-limit window in minutes |
| `TRUSTED_PROXY_COUNT` | Default `1` — trusted proxy hops for real client IP extraction. Set to `0` if no proxy. |
| `METRICS_ENABLED` | `true` — exposes `/user/metrics` for Prometheus to scrape |
| `AUTH_SERVICE_ROLE` | `issuer` — this service signs tokens |
| `TOKEN_ISSUER` | `iss` claim (`https://auth.example.com`); identical in every consumer. Required when `TOKEN_STRICT_VALIDATION=true` |
| `TOKEN_AUDIENCE` | `aud` claim (`https://api.example.com`); identical in every consumer. Required when `TOKEN_STRICT_VALIDATION=true` |
| `TOKEN_STRICT_VALIDATION` | Default `true` — secure-by-default: enforces exact `iss`/`aud` match; boot fails closed unless both are set. `false` only for single-service/local dev |
| `EVENT_SIGNING_ENABLED` | Default `true` — secure-by-default: HMAC-signs auth-event payloads (SSE bridge). Boot fails closed unless `EVENT_SIGNING_KEY` is set |
| `EVENT_SIGNING_KEY` | Shared HMAC secret for event signing; required when `EVENT_SIGNING_ENABLED=true` |
| `EVENT_STREAM_ENABLED` | Default `true` — master switch for the SSE bridge (`GET /private/v1/events/stream`). Set `false` to disable fleet-wide |
| `EVENT_STREAM_BUFFER_SIZE` | Default `256` — ring-buffer depth for `Last-Event-ID` resume |
| `EVENT_STREAM_HEARTBEAT_SECONDS` | Default `15` — heartbeat comment-frame interval; keep below the consumer read timeout and any reverse-proxy idle timeout |
| `EVENT_STREAM_MAX_QUEUE` | Default `64` — per-connection outbound queue depth before a slow consumer is disconnected |

### `api.env` — consumer service only

| Variable | Notes |
| --- | --- |
| `AUTH_SERVICE_ROLE` | `consumer` — verifies tokens, does not sign them |
| `METRICS_ENABLED` | `true` — exposes `/fastapi/metrics` |
| `REVOCATION_CACHE_TTL_SECONDS` | `30` — seconds to cache positive JTI-validation results; event stream evicts early. Set `0` to disable caching (default) |

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
| `./db_data` | Persistent PostgreSQL data |
| `./redis/redis_data` | Persistent Redis snapshots |
| `./prometheus/data` | Prometheus TSDB |
| `./grafana/data` | Grafana dashboards and state |
| `./shared_migrations` | Alembic migration files (auto-created, shared between services) |
| `../../../auth_user_service` | Live source mount — Python changes apply without rebuild |

---

## Database isolation

This stack defaults to **Scenario 2** (per-service isolation): `auth_db` and `api_db`
are created as separate databases with separate users on first volume init. To switch
to a single shared DB or add more services, see the scenario blocks in `.env.example`
and the [database isolation guide](../README.md#database-isolation).

Database provisioning runs **once** on first volume creation. If `.env` DB config
changes after the volume exists, reset with `bash init.sh --reset-db`.

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
# Note: Prometheus and Grafana data in ./prometheus/data and ./grafana/data persist.
# Delete those directories manually if you also want to reset observability state.
bash init.sh --reset-db
```

`--reset-db` removes `db_data/` even when the database container owns it as its
own uid — it falls back to a throwaway root container, so no manual `sudo rm` is
needed on WSL2/Linux bind mounts. `init.sh` also enforces `chmod 600` on runtime
`*.env` files and private keys on every run.

---

## Production deployment

When deploying publicly, replace `traefik/dynamic_conf.yml` with `traefik/production_dynamic_conf.yml`. The production config:

- Ships `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Strict-Transport-Security` (HSTS) **commented out** in `security-headers-prod` — both are opt-in. Uncomment only after TLS is stable with a trusted certificate (and confirm the CSP does not break your frontend/docs). HSTS stays off by default because, once sent, browsers refuse plain HTTP to the host for the full `stsSeconds` even after you disable it.
- Dev `dynamic_conf.yml` has no CSP so Swagger UI works during development.

Also update the `Host` rules in the production config to match your actual FQDN.

---

## Troubleshooting

**Services fail to start immediately** — `auth_user_service` waits for PostgreSQL to pass
its health check (`pg_isready`). PostgreSQL typically initialises in 10–20 s on first boot.
`fastapi_full` then waits for `auth_user_service` to pass its own health check. Watch
the logs with `docker compose logs -f`.

**`changethis` rejection on startup** — replace all `changethis` values in `.env`
and `auth.env`.

**Grafana shows no data** — confirm `METRICS_ENABLED=true` in `auth.env`, then make
at least one request to generate metrics. Check Prometheus targets at
`http://localhost:9090/targets` to confirm the auth service is being scraped.

**Port conflict** — if `5432`, `6379`, `9090`, or `3000` are already in use, identify
the process and stop it, or comment out the conflicting `ports:` entry in
`docker-compose.yml` if you don't need direct host access to that service.

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

After at least one request, check Prometheus has data:

```sh
curl http://localhost:9090/api/v1/query?query=up
```

---

> [Docker Compose examples](../README.md) · [Repository root](https://github.com/mano8/fa-auth-m8/tree/main)
