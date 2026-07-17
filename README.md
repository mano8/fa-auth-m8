# fa-auth-m8 — FastAPI JWT Authentication Microservice

![CI/CD](https://github.com/mano8/fa-auth-m8/actions/workflows/CI.yaml/badge.svg?branch=main)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/edab51cc8805468fb3884e1d9e57ccdc)](https://app.codacy.com/gh/mano8/fa-auth-m8/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![codecov](https://codecov.io/gh/mano8/fa-auth-m8/graph/badge.svg?token=LH7GTT2JZY)](https://codecov.io/gh/mano8/fa-auth-m8)
[![Docker Pulls](https://img.shields.io/docker/pulls/tepochtli/fa-auth-m8)](https://hub.docker.com/r/tepochtli/fa-auth-m8)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/mano8/fa-auth-m8/blob/main/LICENSE)

A production-ready, self-hosted FastAPI (Python 3.14) authentication microservice for Docker Compose. Provides JWT authentication (HS256, RS256, ES256), Google OAuth2 with PKCE, Redis-backed stateful session management, role-based access control (RBAC), API key management with per-key rate limiting, and a private inter-service API — ready to drop into any Docker-based Python microservice stack.

Consumer services validate tokens **locally** using [fastapi-m8](https://github.com/mano8/fastapi-m8) (`pip install fastapi-m8 --upgrade`) — no round-trip to the auth service on every request. `fastapi-m8` bundles [auth-sdk-m8](https://github.com/mano8/auth-sdk-m8) for JWT validation and shared schemas; advanced consumers can also import `auth_sdk_m8` types directly. In `stateful` mode, revocation is checked via a lightweight HTTP call to the auth service private API (`POST /private/v1/jti-status`) instead of connecting to auth Redis directly, keeping the Redis instance private to the auth service.

The included example stacks use `_m8` in their names as a personal naming convention — not a framework requirement. Any stack can be copied and adapted for your own project by renaming the Docker services, network, and env files.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Docker Compose Stacks](#docker-compose-stacks)
- [API Endpoints](#api-endpoints)
- [Quick Start](#quick-start)
- [Docker Hub image](#docker-hub-image)
- [Choosing a Database](#choosing-a-database)
- [Environment Variables](#environment-variables)
- [Infrastructure Resilience](#infrastructure-resilience)
- [Deployment Modes](#deployment-modes)
- [Security defaults](#security-defaults)
- [API Key Authentication](#api-key-authentication)
- [Private API](#private-api)
- [Consumer Service Integration](#consumer-service-integration)
- [Development](#development)
- [Prometheus Metrics](#prometheus-metrics)
- [Dependencies](#dependencies)

---

## Features

- Email/password login with bcrypt password hashing (timing-attack safe)
- Google OAuth2 login with PKCE
- JWT access + refresh token pair (refresh token in HttpOnly cookie, atomically rotated on every use)
- RS256 / ES256 asymmetric signing with JWKS endpoint for zero-downtime key rotation
- Opt-in `iss`/`aud` JWT claim enforcement to prevent cross-service token reuse
- Session tracking and JTI revocation via Redis
- Login rate limiting per email (Redis-backed, namespace-hardened)
- Refresh token rate limiting per user ID — 10 rotations / 5 min, prevents session integrity denial
- **API key authentication** with per-key fixed-window rate limiting (MINUTE / HOUR / DAY / MONTH), `X-RateLimit-*` response headers, and write-behind `last_used_at` tracking
- Role-based access control (`user`, `admin`, `superuser`)
- User management CRUD (superuser only)
- Profile self-service (read, update, password change, delete account, avatar URL)
- Dashboard activity endpoints
- Private inter-service API (protected by shared secret + Docker network isolation)
- MySQL **or** PostgreSQL — switchable via a single env var
- Prometheus metrics (`METRICS_ENABLED=true`) with API key–specific counters and alert rules
- Alembic migrations auto-applied on first start
- VS Code remote debugger support

---

## Architecture

```text
                        Internet
                           │
                    ┌──────▼──────┐
                    │   Traefik   │  TLS termination, IP forwarding
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
   ┌──────▼──────┐  ┌──────▼──────┐  ┌─────▼──────┐
   │ auth-service│  │  consumer   │  │  Prometheus │
   │  :8000      │  │  service    │  │  + Grafana  │
   └──┬──────┬───┘  └─────────────┘  └────────────┘
      │      │
┌─────▼──┐ ┌─▼──────────┐
│ MySQL/ │ │ Redis :6379 │
│ Postgres│ └────────────┘
└────────┘
```

Consumer services validate tokens locally (JWT signature check + optional Redis blacklist via `fastapi-m8`) — no per-request call to the auth service. Other services on the same Docker network can also call the private API at `http://auth-service:8000/user/private/` for operations such as creating users programmatically.

---

## Docker Compose Stacks

Six ready-to-run stacks are provided under [`examples/docker_compose/`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose). See the [stack selection guide](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose#which-stack-should-i-use) for help choosing.

| Stack | Database | Algorithm | Token mode | Observability | Notes |
| ----- | -------- | --------- | ---------- | ------------- | ----- |
| [`quickstart_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/quickstart_m8) | MariaDB | HS256 | `stateful` | — | **Start here** — simplest onboarding |
| [`postgres_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/postgres_m8) | PostgreSQL 16 | HS256 | `stateful` | — | PostgreSQL variant |
| [`rs256_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/rs256_m8) | MariaDB | RS256 | `hybrid` | — | Asymmetric signing + JWKS |
| [`metrics_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/metrics_m8) | PostgreSQL 16 | HS256 | `stateful` | Prometheus + Grafana | Metrics dashboards |
| [`hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8) | PostgreSQL 16 | RS256 | `stateful` | Prometheus + Grafana | Container hardening + Docker Hub image |
| [`vault_dev_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/vault_dev_m8) | PostgreSQL 18 | RS256 | `stateful` | Prometheus + Grafana | HashiCorp Vault (dev mode) + Docker Hub image |

**Start here →** [`quickstart_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/quickstart_m8) for the fastest path to a running stack.

All stacks include `healthcheck` probes and `restart: unless-stopped` on `auth_user_service` and `fastapi_full`. The consumer service waits for the auth service health check to pass (`service_healthy`) before starting.

### Token modes at a glance

The `TOKEN_MODE` column in the table above controls how tokens are validated across your services:

| Mode | Redis for JWT | Instant revocation | Google OAuth | Best for |
| ---- | ------------- | ------------------ | ------------ | -------- |
| `stateless` | No | ✗ | ✗ | Maximum scalability, no revocation needed |
| `hybrid` | Refresh only | Refresh tokens only | ✓ | Balance: scalable access + revocable refresh |
| `stateful` | Yes (every request) | ✓ | ✓ | Instant logout guarantee, highest security |

`stateless` disables Google OAuth (PKCE requires Redis). `hybrid` leaves a stolen access token valid until expiry after logout; use `stateful` if instant revocation is required.

---

## API Endpoints

All routes are prefixed with `API_PREFIX` (default `/user`).

| Tag | Method | Path | Auth | Description |
| --- | ------ | ---- | ---- | ----------- |
| meta | GET | `/meta` | — | Static service/version/contract identity (`ServiceMeta`) for client compat checks; cacheable, read pre-auth |
| meta | GET | `/ping` | — | Dependency-free liveness probe → `{"status": "ok"}` (single-mounted at `{API_PREFIX}/ping` since auth-sdk-m8 2.0.0) |
| health | GET | `/health/` | — (detail: `X-Internal-Token`) | Public body is the constant `{"status":"ok"}`; Redis/database/effective-token-mode readiness detail is gated on `HEALTH_DETAIL_CREDENTIAL` (plan 9.4) |
| well-known | GET | `/.well-known/jwks.json` | — | JWKS endpoint (RS256/ES256 public key; `{"keys":[]}` for HS256) |
| login | POST | `/login/access-token` | — | Email/password login — returns access token, sets refresh cookie |
| login | POST | `/login/refresh-token/` | — | Refresh access token from HttpOnly cookie |
| login | POST | `/login/logout/` | JWT | Revoke session, blacklist JTI, clear cookie |
| login | POST | `/login/test-token/` | JWT | Validate access token, return current user |
| google-api | GET | `/google-api/login-url/` | — | Return Google OAuth2 authorization URL (native-app PKCE flow) |
| google-api | POST | `/google-api/exchange/` | — | One-time auth code exchange for tokens (PKCE verified, GETDEL atomic) |
| google-auth | GET | `/google-auth/oauth-callback/` | — | Google OAuth2 PKCE callback — exchange code, create/update user |
| profile | GET | `/profile/get/me/` | JWT | Read own profile |
| profile | PATCH | `/profile/update/me/` | JWT | Update own profile (`email`, `full_name`, `avatar` only — explicit allowlist) |
| profile | PATCH | `/profile/me/password/` | JWT | Change own password |
| profile | DELETE | `/profile/delete/me/` | JWT | Delete own account (cascades to the user's sessions, API keys, and rate-limit rows) |
| api-keys | GET | `/profile/api-keys/verify` | X-API-Key | Validate key header, enforce rate limits, return key metadata |
| api-keys | POST | `/profile/api-keys/` | JWT | Create API key — plaintext returned once, never stored |
| api-keys | GET | `/profile/api-keys/` | JWT | List own API keys (metadata only) |
| api-keys | GET | `/profile/api-keys/{key_id}` | JWT | Get single key metadata |
| api-keys | DELETE | `/profile/api-keys/{key_id}` | JWT | Revoke API key |
| sessions | GET | `/sessions/` | superuser | List all sessions (paginated) |
| sessions | GET | `/sessions/get/{session_id}/` | superuser | Get session by ID |
| sessions | GET | `/sessions/get-by-user/{user_id}/` | superuser | Get session by user ID |
| sessions | GET | `/sessions/get-current/` | JWT | Get own current session |
| sessions | POST | `/sessions/refresh-google-tokens/` | JWT | Refresh external Google tokens |
| sessions | DELETE | `/sessions/delete-by-user/{user_id}/` | superuser | Delete all sessions for a user |
| sessions | DELETE | `/sessions/delete/{session_id}/` | superuser | Delete specific session |
| users | GET | `/users/` | superuser | List all users (paginated) |
| users | POST | `/users/new_user/` | superuser | Create user with password |
| users | POST | `/users/signup/` | superuser | Register user (no password set) |
| users | GET | `/users/get/{user_id}/` | superuser | Get user by ID |
| users | PATCH | `/users/update/{user_id}/` | superuser | Update user |
| users | DELETE | `/users/delete/{user_id}/` | superuser | Delete user (cascades to the user's sessions, API keys, and rate-limit rows) |
| dashboard | GET | `/dashboard/users/activity/` | JWT | All-user activity stats (monthly) |
| dashboard | GET | `/dashboard/users/activity/current/` | JWT | Own activity stats (monthly) |
| metrics | GET | `/metrics` | — | Prometheus metrics (`METRICS_ENABLED=true` only) |
| private | POST | `/private/users/` | X-Internal-Client + X-Internal-Token (`user-create`) | Create user (inter-service, Docker network only) |
| private | POST | `/private/v1/jti-status` | X-Internal-Client + X-Internal-Token (`introspection`) | Check whether an access-token JTI is revoked (inter-service) |
| private | GET | `/private/v1/events/stream` | X-Internal-Client + X-Internal-Token (`event-stream`) | SSE bridge of `session-revoked` / `user-deleted` events (inter-service) |

**Service triad (`/meta`, `/ping`, `/health/`).** `/ping` answers "is the process up?" (liveness — point container/orchestrator liveness probes here; never touches a dependency), `/health/` answers liveness publicly with a constant `{"status":"ok"}` and "are dependencies reachable?" (readiness — Redis/DB) **only in its credential-gated detail body** (the public body never reflects degradation — plan 9.4 Design B), and `/meta` answers "what version/contract is this?" (client compatibility, read pre-auth — satisfies `@fa-m8/astro-auth-m8`'s `assertFaAuthM8Compatibility`). `/meta` + `/ping` are the shared auth-sdk-m8 routes (`mount_service_meta`); the issuer mounts them directly since it doesn't use `fastapi_m8.create_app`. Since auth-sdk-m8 2.0.0 `/ping` is **single-mounted** at `{API_PREFIX}/ping` (the root `/ping` is no longer served when a prefix is set) and advertised in the schema — point container/orchestrator liveness probes at `{API_PREFIX}/ping`.

Interactive docs at `{BACKEND_HOST}{API_PREFIX}/docs` when `SET_DOCS=true` **and** `ENVIRONMENT ≠ production`. In production docs are suppressed by default; set `SERVE_DOCS_IN_PRODUCTION=true` to explicitly enable them (emits a startup warning — use only for public/open-source APIs).

---

## Quick Start

### 1. Choose a stack

```bash
cd examples/docker_compose/quickstart_m8      # fastest start — HS256 + stateful mode
# or
cd examples/docker_compose/rs256_m8           # asymmetric RS256 + JWKS
```

See the [Docker Compose stack guide](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose) to pick the right stack.

### 2. Copy env files and generate secrets

```bash
cp .env.example .env
cp auth.env.example auth.env
cp api.env.example api.env
# Fill in all `changethis` values in .env, auth.env and api.env
```

Generate secrets with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 3. Install mkcert (optional — for browser-trusted TLS)

> **TLS works without this step.** Each stack includes a `cert-init` Docker service that generates a self-signed certificate automatically on the first `docker compose up`. Browsers will show a certificate warning in that case. Install mkcert only if you want a fully trusted cert with no browser warnings.

`mkcert` creates a local CA trusted by your OS and browsers, eliminating the `ERR_CERT_AUTHORITY_INVALID` warning and silent `fetch()` failures in Chrome extensions.

```bash
# Windows
winget install FiloSottile.mkcert   # or: choco install mkcert

# macOS
brew install mkcert && brew install nss   # nss = Firefox support

# Linux — see https://github.com/FiloSottile/mkcert#linux
```

After installing, run **once** to register the local CA system-wide:

```bash
mkcert -install
```

`init.sh` detects `mkcert` automatically and falls back to a self-signed OpenSSL certificate if it is not installed (browsers will still warn in that case).

#### Browser TLS compatibility

| Browser | With mkcert | Without mkcert |
| ------- | ----------- | -------------- |
| Chrome, Edge, Brave, Opera, Vivaldi | ✅ Trusted automatically | ⚠️ Cert warning |
| Safari (macOS) | ✅ Trusted automatically | ⚠️ Cert warning |
| Firefox | ⚠️ Manual CA import needed | ⚠️ Cert warning |

Firefox uses its own NSS certificate store and does not inherit the OS trust store.
See `traefik/certs/README_DEV.md` inside any example stack for the step-by-step
Firefox CA import walkthrough.

### 4. Generate keys and TLS certificate

```bash
bash init.sh
# RS256/ES256 stacks: also generates the key pair and writes ACCESS_KEY_ID
```

> **Windows:** use **Git Bash** (included with Git for Windows) or **WSL**.

### 5. Start the stack

```bash
docker compose up --build
```

Alembic migrations run automatically. The first start seeds the superuser from `FIRST_SUPERUSER` / `FIRST_SUPERUSER_PASSWORD`.

### 6. Verify

```http
GET http://localhost:9000/user/health/
```

> `/user/health` answers publicly on the `websecure` entryPoint (port 4430/443) with a **constant shallow body** (`{"status":"ok"}`) — it never reflects degradation. Its full infrastructure detail is gated at the app layer on `HEALTH_DETAIL_CREDENTIAL` (fail-closed). `/user/metrics` and `/user/private` stay internal-only — reachable only on the `api` entryPoint (port 9000, localhost-bound) and blocked on `websecure` (plan 9.4, Design B).

### 7. Adapt for your own project

The example stacks are ready-to-copy templates. To use one as the base for a new project:

- Copy the stack directory and rename it.
- In `docker-compose.yml`, rename the Docker services and internal network to match your project.
- Update all `changethis` values in the env files.
- Add your own microservices to `docker-compose.yml` on the same internal network.

### 8. Going to production (`hardened_m8` overlay)

`hardened_m8` ships a **thin production overlay** so the same stack serves both a
safe dev/home-lab default *and* a hardened production posture — no second tree to
drift, nothing dangerous default-on. The base `docker-compose.yml` is unchanged
when the overlay is not applied; the overlay is what turns the production-only
options on.

```bash
cd examples/docker_compose/hardened_m8
cp .env.production.example .env
cp auth.env.production.example auth.env.production
cp api.env.production.example api.env.production
# Fill in every `changethis`, set your real FQDNs, and provision real TLS certs
# at ./traefik/certs/local.crt + local.key (the overlay never self-signs).
bash init.sh
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

> Requires Docker Compose **v2.24+** (the overlay uses the `!reset` / `!override`
> merge tags).

What the overlay changes vs. the dev default:

| Area | Dev default | Production overlay |
| ---- | ----------- | ------------------ |
| Mode | `ENVIRONMENT=local`, `STRICT_PRODUCTION_MODE=false` | `production` + `STRICT_PRODUCTION_MODE=true` (config-health is fatal, not warn) |
| Docs | `SET_DOCS=true` | off (`SET_DOCS=false`; opt back in only with `SERVE_DOCS_IN_PRODUCTION=true`) |
| TLS certs | `cert-init` self-signs | `cert-init` is a fail-closed presence check for operator certs |
| Published ports | app `:8000`, dashboard `:8080`, internal `:9000`, DB/Redis/Prometheus/Grafana on loopback | only `:80` (HTTP→HTTPS redirect) and `:443`; everything else Docker-network only |
| Host rules | `Host(`localhost`)` | FQDN rules + app-layer `ALLOWED_HOSTS` |
| Cookies | — | `SESSION_COOKIE_SECURE=true` |
| Images | auth pinned, consumer builds locally | pinned (never `:latest`) |

Startup **fails closed** under the overlay on placeholder/duplicate secrets,
missing `ALLOWED_HOSTS`, missing `TOKEN_ISSUER`/`TOKEN_AUDIENCE`, localhost CORS
origins, unsafe internal HTTP, or unsafe event-signing rollout. HSTS stays
opt-in even in production (it is browser-persisted and hard to reverse).

**Migrations.** The stack runs `alembic upgrade head` automatically on `up`
(idempotent). For a single-node deployment this is kept as-is. For
multi-replica / zero-downtime rollouts, run it as a one-shot **before** starting
the app instead:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml \
  run --rm auth_user_service alembic upgrade head
```

---

## Docker Hub image

The published image is available at:

```bash
docker pull tepochtli/fa-auth-m8:latest
```

[![Docker Pulls](https://img.shields.io/docker/pulls/tepochtli/fa-auth-m8)](https://hub.docker.com/r/tepochtli/fa-auth-m8)

### Tags

| Tag | Description |
| --- | ----------- |
| `latest` | Latest release from the `main` branch |
| `x.y.z` (e.g. `1.0.0`) | Pinned release — recommended for production |

### Using the published image in a Compose stack

The example stacks under `examples/docker_compose/` use `build:` to build the
service image locally from source. To use the published image instead, replace
the `build:` block in the `auth_user_service` service with an `image:` line:

```yaml
# Replace this:
auth_user_service:
  build:
    context: ../../../
    dockerfile: ./auth_user_service/Dockerfile

# With this:
auth_user_service:
  image: tepochtli/fa-auth-m8:1.1.0   # pin to a specific release for production
```

All env files, volumes, labels, and `depends_on` entries remain unchanged —
only the `build:` block is replaced.

### When to build locally vs. use the published image

| Scenario | Recommendation |
| -------- | -------------- |
| Production deployment | `image: tepochtli/fa-auth-m8:x.y.z` — pinned, reproducible |
| Evaluating or quick start | `image: tepochtli/fa-auth-m8:latest` — always current |
| Active development / custom changes | `build:` (default in example stacks) — local source |

---

## Choosing a Database

Set `SELECTED_DB` in `.env` (or `auth.env`):

| Value | Driver | Default port |
| ----- | ------ | ------------ |
| `Mysql` (default) | `pymysql` / `aiomysql` | 3306 |
| `Postgres` | `psycopg2` / `asyncpg` | 5432 |

---

## Environment Variables

### Core

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `DOMAIN` | yes | — | Public domain (e.g. `localhost`) |
| `ENVIRONMENT` | yes | — | `local` \| `development` \| `staging` \| `production` |
| `API_PREFIX` | yes | `/user` | URL prefix for all routes |
| `PROJECT_NAME` | yes | — | Project name shown in docs |
| `STACK_NAME` | yes | — | Docker Compose stack slug |
| `BACKEND_HOST` | yes | — | Full backend URL (e.g. `http://127.0.0.1:9000`) |
| `FRONTEND_HOST` | yes | — | Full frontend URL (e.g. `http://localhost:5173`) |
| `BACKEND_CORS_ORIGINS` | yes | — | Comma-separated allowed origins |
| `TABLES_PREFIX` | no | `auth` | DB table name prefix (e.g. `auth_user`, `auth_api_key`) |
| `SET_DOCS` | no | `true` | Enable Swagger UI at `{API_PREFIX}/docs`. Suppressed in production unless `SERVE_DOCS_IN_PRODUCTION=true`. |
| `SET_REDOC` | no | `true` | Enable ReDoc at `{API_PREFIX}/redoc`. Same production gate as `SET_DOCS`. |
| `SET_OPEN_API` | no | `true` | Enable OpenAPI schema at `{API_PREFIX}/openapi.json`. Same production gate as `SET_DOCS`. |
| `SERVE_DOCS_IN_PRODUCTION` | no | `false` | Explicitly serve docs in production (`auth-sdk-m8 ≥ 0.7.3`). Emits a startup warning. Only for public/open-source APIs. |

### Tokens

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `TOKEN_MODE` | no | `stateful` | `stateless` \| `hybrid` \| `stateful` — controls Redis usage and JTI revocation |
| `ACCESS_TOKEN_ALGORITHM` | no | `RS256` | Signing algorithm for access tokens. Secure-by-default `RS256` (asymmetric + JWKS); `ES256` also supported; `HS256` is a documented opt-out (symmetric) |
| `REFRESH_TOKEN_ALGORITHM` | no | `HS256` | Signing algorithm for refresh tokens |
| `ACCESS_SECRET_KEY` | HS256 only | — | Symmetric signing key for access tokens |
| `REFRESH_SECRET_KEY` | yes | — | Signing key for refresh tokens (always HS256) |
| `REFRESH_SECRET_KEY_OLD` | no | — | Previous refresh signing key. Set during key rotation to allow old-key tokens to remain valid for the duration of their TTL. Remove once all pre-rotation refresh tokens have expired. |
| `ACCESS_PRIVATE_KEY_FILE` | RS256/ES256 only | — | Path to PEM private key file (mounted into container) |
| `ACCESS_PUBLIC_KEY_FILE` | RS256/ES256 only | — | Path to PEM public key file (distributed to consumers) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_MINUTES` | no | `120` | Refresh token lifetime |
| `REFRESH_TOKEN_COOKIE_EXPIRE_SECONDS` | no | `3600` | Refresh cookie max-age |
| `SESSION_SECRET` | yes | — | Signing key for the `SessionMiddleware` cookie. Must be distinct from `TOKENS_ENCRYPTION_KEY` (key separation) so rotating the session key does not invalidate encrypted tokens. Rotation is single-key (Starlette exposes no key-list): the cookie `max_age` (3600s) bounds the blast radius to ≤1h of re-auth — there is no `_OLD` fallback. |
| `TOKENS_ENCRYPTION_KEY` | yes | — | Fernet key encrypting external/refresh token payloads at rest in Redis |
| `TOKENS_ENCRYPTION_KEY_OLD` | no | — | Previous `TOKENS_ENCRYPTION_KEY`. Set during a no-downtime key rotation so tokens encrypted under the old key stay decryptable (`MultiFernet` new→old fallback) while new writes use the current key. Remove once every stored token has been re-encrypted under / expired past the new key. |
| `TOKEN_ISSUER` | if strict | — | `iss` claim embedded in issued tokens; validators require an exact match. **Required at boot when `TOKEN_STRICT_VALIDATION=true` (the default).** |
| `TOKEN_AUDIENCE` | if strict | — | `aud` claim embedded in issued tokens; validators require an exact match. **Required at boot when `TOKEN_STRICT_VALIDATION=true` (the default).** |
| `TOKEN_STRICT_VALIDATION` | no | `true` | Secure-by-default strict profile (`auth-sdk-m8 ≥ 1.0.0`): enforces `iss`/`aud` binding and pins the configured algorithm; the service fails closed at boot unless `TOKEN_ISSUER`/`TOKEN_AUDIENCE` are set. Set `false` to opt out (legacy/local), enforcing `iss`/`aud` only when configured. |
| `ACCESS_KEY_ID` | no | — | Explicit `kid` in JWT headers and JWKS; auto-derived from key fingerprint when unset |
| `AUTH_SERVICE_ROLE` | no | `issuer` | `issuer` (auth service) or `consumer` (downstream services) |
| `JWKS_URI` | no | — | Consumer services: JWKS endpoint URL; enables automatic `JwksKeyResolver` wiring |
| `JWKS_CACHE_TTL_SECONDS` | no | `300` | JWKS key cache TTL in seconds |

**RS256 / ES256 (secure-by-default)** — `ACCESS_TOKEN_ALGORITHM` defaults to `RS256`: the auth service signs with the mounted private key and publishes JWKS (see below). RSA keys must be ≥ 2048-bit (enforced at boot).

**HS256 (opt-out)** — set `ACCESS_TOKEN_ALGORITHM=HS256`, `ACCESS_SECRET_KEY`, and `REFRESH_SECRET_KEY`; leave asymmetric key vars blank.

**Generating asymmetric keys** — set `ACCESS_PRIVATE_KEY_FILE` and `ACCESS_PUBLIC_KEY_FILE`, then mount the key files into the container (see `examples/docker_compose/rs256_m8/keys/`). Generate a key pair:

```bash
# RS256
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# ES256
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

Or use `bash init.sh` in any asymmetric stack — it generates the correct key type automatically.

**Migrating an existing HS256 deployment** — `auth-sdk-m8 ≥ 1.0.0` flips the defaults to RS256 + strict `iss`/`aud`. Existing deployments have two coherent paths:

- **Adopt the secure default (recommended):** generate an RSA key pair, set `ACCESS_PRIVATE_KEY_FILE` / `ACCESS_PUBLIC_KEY_FILE`, point consumers at `JWKS_URI`, and set the same `TOKEN_ISSUER` / `TOKEN_AUDIENCE` on the auth service and every consumer. Roll the public key / JWKS out to consumers **before** switching the issuer so in-flight tokens still validate.
- **Stay on the legacy posture (opt-out):** set `ACCESS_TOKEN_ALGORITHM=HS256` (with `ACCESS_SECRET_KEY`) and `TOKEN_STRICT_VALIDATION=false`. The service then behaves as it did before 1.0.0 — `iss`/`aud` enforced only when configured.

### Database

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `SELECTED_DB` | no | `Mysql` | `Mysql` or `Postgres` |
| `DB_HOST` | yes | — | Database host |
| `DB_PORT` | yes | — | Database port |
| `DB_DATABASE` | yes | — | Database name |
| `DB_USER` | yes | — | Database user |
| `DB_PASSWORD` | yes | — | Database password |

### Redis

| Variable | Required | Description |
| -------- | -------- | ----------- |
| `REDIS_HOST` | yes | Redis host |
| `REDIS_PORT` | yes | Redis port |
| `REDIS_USER` | yes | Redis user |
| `REDIS_PASSWORD` | yes | Redis password |
| `REDIS_SSL` | no | Enable TLS for the Redis connection pool (default: `false`). Set `true` when Redis is reached over a network boundary in staging/production. |
| `REDIS_SSL_CA` | no | Path to CA certificate file. **Required when `REDIS_SSL=true`** — without it the connection pool cannot verify the server cert and will raise `CERTIFICATE_VERIFY_FAILED`. |
| `REDIS_SSL_CERT` | no | Path to client certificate for mTLS. Must be set together with `REDIS_SSL_KEY`; cannot be set without it. |
| `REDIS_SSL_KEY` | no | Path to client private key for mTLS. Must be set together with `REDIS_SSL_CERT`; cannot be set without it. |

### Auth & OAuth

| Variable | Required | Description |
| -------- | -------- | ----------- |
| `FIRST_SUPERUSER` | yes | Email of the bootstrap superuser — used only on first run |
| `FIRST_SUPERUSER_PASSWORD` | yes | Password of the bootstrap superuser — used only on first run |
| `GOOGLE_CLIENT_ID` | no | Google OAuth2 client ID |
| `GOOGLE_CLIENT_SECRET` | no | Google OAuth2 client secret |
| `GOOGLE_OAUTH_REDIRECT_URI` | no | Fixed backend callback URI for native-app PKCE OAuth. Must match Google Console exactly. Defaults to auto-derived from request URL when empty. |
| `OAUTH_ALLOWED_REDIRECT_SCHEMES` | no | URI scheme(s) accepted as `redirect_target` at `/google-api/login-url/` (default `chrome-extension://`). Add `https://` only for trusted web clients; add `http://` only for local development. |
| `OAUTH_ALLOWED_REDIRECT_PREFIXES` | no | Optional full-URI prefix allowlist. Required for `http://` and `https://` redirects to pin trusted callback origins; optional for native public-client schemes. Plain HTTP is limited to localhost and rejected in production/staging. |
| `CORS_ALLOWED_ORIGIN_SCHEMES` | no | Scheme-level CORS origins for native-app `fetch()` calls (e.g. `chrome-extension://`). |
| `PRIVATE_API_SECRET` | yes | Signs the short-TTL service tokens and gates the `/health` detail body + `/metrics`. **No longer a private-route gate** (the legacy shared `X-Internal-Token` path was retired in v1.0.0 — `PRIVATE_API_CONSUMERS` replaces it). |
| `PRIVATE_API_CONSUMERS` | yes¹ | Per-consumer private-API credentials: JSON map of consumer id → `{secret, scopes}` (scopes: `introspection` / `event-stream` / `user-create`, deny-by-default; `secret` plaintext or hashed `sha256$<salt>$<digest>`). The **only** private-API auth model — each consumer presents `X-Internal-Client` + `X-Internal-Token` (or exchanges it for a service token). ¹Empty is allowed but then every `/private/*` call fails closed (`401`) and the service-token exchange is disabled (`404`). |

### Event Signing

`auth-sdk-m8 ≥ 1.0.0` introduces **secure-by-default event signing** (F3): when `EVENT_SIGNING_ENABLED=true` (the default), the service **fails closed at boot** unless a strong `EVENT_SIGNING_KEY` is configured. Set the key in `auth_user_service/.env` and in every consumer stack's env file.

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `EVENT_SIGNING_ENABLED` | no | `true` | Master switch. When `true`, `EVENT_SIGNING_KEY` is **required at startup** — the service will not boot without it. Set `false` only to disable event signing entirely (opt-out). |
| `EVENT_SIGNING_KEY` | if enabled | — | HMAC key used to sign event-bus payloads. Must satisfy the secret-key strength policy (32+ chars, mixed-case, digit, non-alphanumeric). **Never use the dev placeholder in production.** |
| `EVENT_SIGNING_ACCEPT_UNSIGNED` | no | `false` | Transitional flag for rolling upgrades: when `true`, consumers accept signed or unsigned messages (still reject forged signatures). Flip back to `false` once every publisher signs. |

> **Auth Redis is private to fa-auth-m8.** Consumer services check revocation via the HTTP private API (`POST /private/v1/jti-status`) — they never connect to the auth Redis directly. Auth-state changes are pushed to consumers over the authenticated SSE bridge below (same private API, same trust channel), so there is **no shared broadcast medium and no second Redis** to wire.

### Auth Event Stream (SSE bridge)

fa-auth-m8 pushes its own auth-state changes to backend consumers over an authenticated **Server-Sent Events** stream on the private API: `GET /private/v1/events/stream` (gated by the same per-consumer credential as `jti-status`, requiring the `event-stream` scope). Consumers receive `session-revoked` and `user-deleted` events and evict locally cached token-validation state ahead of natural expiry.

> **Accelerator, not authority.** Push is a best-effort latency optimisation. The JTI blacklist behind `POST /private/v1/jti-status` remains the revocation authority — a consumer that misses every event is still correct, just slower to converge. So stream loss is never fatal: the service keeps enforcing revocation over the HTTP authority path.

Each event `data` frame is HMAC-signed with the shared `EVENT_SIGNING_KEY` (reused from Event Signing above — no separate key); consumers verify it before acting. Reconnecting consumers send `Last-Event-ID`: a still-buffered gap is replayed exactly, while an unresumable gap (fa-auth restarted, or the id evicted from the ring buffer) is signalled with an `event: gap` frame, after which the consumer flushes all cached validation state.

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `EVENT_STREAM_ENABLED` | no | `true` | Master switch for the SSE bridge. When `false`, the endpoint returns 404 and emission is a fleet-wide no-op. |
| `EVENT_STREAM_BUFFER_SIZE` | no | `256` | Ring-buffer depth (events retained for `Last-Event-ID` resume). |
| `EVENT_STREAM_HEARTBEAT_SECONDS` | no | `15` | Heartbeat comment-frame interval. Keep below the consumer read timeout and any reverse-proxy idle timeout. |
| `EVENT_STREAM_MAX_QUEUE` | no | `64` | Per-connection outbound queue depth before a slow consumer is disconnected (it reconnects and resumes/flushes). Never blocks the emitting request. |

> **Reverse proxies:** SSE needs response buffering **disabled** so frames flush immediately. The endpoint sends `X-Accel-Buffering: no` (honoured by nginx); for other proxies, disable response buffering and set the idle/read timeout above `EVENT_STREAM_HEARTBEAT_SECONDS`.

### Auth Degradation Policy

Controls what happens to each security control when Redis is unavailable. All settings are optional; the defaults represent the recommended production posture.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `AUTH_STRICT_MODE` | `false` | When `true`, overrides all per-control modes to `fail_closed` |
| `REFRESH_VALIDATION_FAILURE_MODE` | `fail_closed` | Refresh allowlist check unavailable → `fail_closed`: 503 \| `fail_open`: skip check |
| `SESSION_WRITE_FAILURE_MODE` | `fail_closed` | Token revocation on logout fails → `fail_closed`: 503 \| `fail_open`: silent skip |
| `RATE_LIMIT_FAILURE_MODE` | `fail_open` | Rate limiter unavailable → `fail_closed`: 503 \| `fail_open`: skip check |
| `ACCESS_REVOCATION_FAILURE_MODE` | `fail_open` | Access token blacklist check unavailable → `fail_closed`: 503 \| `fail_open`: skip |

Default posture: refresh validation and session writes **fail closed** (logout is authoritative; unverifiable refresh tokens are rejected). Rate limiting and access revocation **fail open** (short token TTL bounds the exposure window; availability is preserved).

Every degraded-mode decision emits an `auth_degraded_decision_total` counter (labels: `control`, `mode`, `reason`) — see the [Prometheus metrics](#prometheus-metrics) table for full label values.

### Login & Refresh Rate Limiting

Controls the fixed-window rate limits applied to the login and refresh-token endpoints (Redis-backed). All settings are optional; the defaults represent the recommended security posture.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `LOGIN_RATE_LIMIT_REQUESTS` | `5` | Max login attempts per window per email before 429 |
| `LOGIN_RATE_LIMIT_WINDOW_MINUTES` | `15` | Brute-force window in minutes |
| `REFRESH_RATE_LIMIT_REQUESTS` | `10` | Max refresh token rotations per window per user |
| `REFRESH_RATE_LIMIT_WINDOW_MINUTES` | `5` | Churn-prevention window in minutes |

A startup warning is logged if the effective rate (requests ÷ window) exceeds 5 req/min for login or 20 req/min for refresh. When Redis is unavailable, behaviour falls back to `RATE_LIMIT_FAILURE_MODE`.

### API Key Rate Limiting

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `API_KEY_STRICT_RATE_LIMIT` | no | `false` | Force fail-closed (503) API-key verification when Redis is unavailable. **Auto-enabled** in production/strict (`ENVIRONMENT=production`, `STRICT_PRODUCTION_MODE=true`, or `AUTH_STRICT_MODE=true`); this flag only forces it on elsewhere |
| `API_KEY_DEFAULT_LIMIT_MINUTE` | no | `60` | Default requests per minute (`0` = disabled) |
| `API_KEY_DEFAULT_LIMIT_HOUR` | no | `1000` | Default requests per hour |
| `API_KEY_DEFAULT_LIMIT_DAY` | no | `10000` | Default requests per day |
| `API_KEY_DEFAULT_LIMIT_MONTH` | no | `200000` | Default requests per month |
| `API_KEY_MAX_PER_USER` | no | `10` | Maximum API keys a user may create |

### Observability

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `METRICS_ENABLED` | no | `false` | Expose `GET /metrics` Prometheus endpoint |
| `METRICS_GROUPS` | no | `all` | Comma-separated groups: `all` \| `traffic` \| `performance` \| `reliability` \| `health` \| `auth` |
| `SENTRY_DSN` | no | — | Sentry DSN for error tracking |

### Response Security Headers

`auth-sdk-m8 ≥ 1.2.1` adds a shared application-level hardening layer
(`add_security_headers_middleware`) wired into the auth service — and into every
`fastapi-m8` consumer via `create_app`. Headers are applied on **every** response
(including error responses raised before the route handler) in **three tiers**:

| Tier | Headers | When applied |
| ---- | ------- | ------------ |
| **Always-on** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` | Every environment (whenever `SECURITY_HEADERS_ENABLED`). Safe for Swagger/ReDoc/HMR. |
| **Production-gated** | `Referrer-Policy`, `Permissions-Policy` | `ENVIRONMENT=production` or `STRICT_PRODUCTION_MODE=true` — the same gate as docs hiding. |
| **Express opt-in** | `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP) | Only when `HSTS_ENABLED` / `CONTENT_SECURITY_POLICY_ENABLED` — **never on `local`**, even if opted in. |

HSTS and CSP are **browser-persisted and hard to reverse** (enabling HSTS on a host
writes a long-lived HTTPS-only record — on `localhost` it force-upgrades every local
service to HTTPS), so they are **off by default**, decoupled from the production gate,
and hard-blocked on `local`. A TLS-terminated `staging` stack can opt in without
masquerading as production.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SECURITY_HEADERS_ENABLED` | `true` | Master switch. Set `false` to suppress every tier, even in production. |
| `HSTS_ENABLED` | `false` | Express opt-in for `Strict-Transport-Security`. Never emitted on `local`. |
| `HSTS_MAX_AGE` | `31536000` | HSTS max-age in seconds. `0` also disables the header. Only applies when `HSTS_ENABLED`. |
| `HSTS_INCLUDE_SUBDOMAINS` | `true` | Append `includeSubDomains` to the HSTS header. |
| `CONTENT_SECURITY_POLICY_ENABLED` | `false` | Express opt-in for `Content-Security-Policy`. Never emitted on `local`. |
| `CONTENT_SECURITY_POLICY` | — | CSP value used when enabled. Unset → tight API default (`default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`). Override for services that serve HTML. |
| `REFERRER_POLICY` | `strict-origin-when-cross-origin` | `Referrer-Policy` header value (production-gated tier). |
| `PERMISSIONS_POLICY` | `accelerometer=(), camera=(), geolocation=(), …` | `Permissions-Policy` header value (production-gated tier). |

> **Behaviour change (auth-sdk-m8 1.2.1 / fastapi-m8 1.5.0):** HSTS and CSP were
> emitted automatically under the production gate in earlier releases. They are now
> **off until explicitly enabled** via `HSTS_ENABLED=true` /
> `CONTENT_SECURITY_POLICY_ENABLED=true`.

### Deployment

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `API_BIND_IP` | `127.0.0.1` | Host IP Traefik binds port 9000 to. Set to `0.0.0.0` for LAN/public exposure |
| `TRUSTED_PROXY_COUNT` | `1` | Number of trusted reverse-proxy hops in front of this service. Used to extract the real client IP from `X-Forwarded-For` (leftmost entry). Set to `0` to ignore XFF entirely (no proxy in front). |
| `TRUSTED_PROXY_IPS` | `172.16.0.0/12` | CIDR(s) Uvicorn trusts as reverse-proxy source for `X-Forwarded-For` |
| `STRICT_PRODUCTION_MODE` | `false` | When `true`, enforce production-grade checks (e.g. secure cookies) even in non-production environments |

---

## Infrastructure Resilience

The service degrades gracefully when Redis or the database is temporarily unavailable.

### Redis unavailable

Behaviour when Redis is down is controlled by the [Auth Degradation Policy](#auth-degradation-policy) settings. The table below shows the default posture (`fail_closed` for refresh + logout, `fail_open` for rate limiting + access revocation):

| `TOKEN_MODE` | Login | Refresh | Logout | Google OAuth |
| ------------ | ----- | ------- | ------ | ------------ |
| `stateless` | ✅ unaffected | ✅ unaffected | ✅ unaffected | ❌ 503 (PKCE requires Redis) |
| `hybrid` | ✅ works, rate limiting skipped | ❌ 503 (`REFRESH_VALIDATION_FAILURE_MODE=fail_closed`) | ❌ 503 (`SESSION_WRITE_FAILURE_MODE=fail_closed`) | ❌ 503 |
| `stateful` | ✅ works, rate limiting skipped | ❌ 503 (`REFRESH_VALIDATION_FAILURE_MODE=fail_closed`) | ❌ 503 (`SESSION_WRITE_FAILURE_MODE=fail_closed`) | ❌ 503 |

Set `REFRESH_VALIDATION_FAILURE_MODE=fail_open` and `SESSION_WRITE_FAILURE_MODE=fail_open` to restore the previous fail-open behaviour (tokens accepted without allowlist check; logout silently skips revocation).

In `stateful`/`hybrid` mode with Redis down, the `/health/` endpoint reflects `effective_mode: stateless_degraded` and a `CRITICAL` log is emitted at startup.

#### Degradation contract

The service operates under two stable states with a brief transient inconsistency regime between them:

| State | Condition | Authorization correctness |
| ----- | --------- | ------------------------- |
| **Healthy** | Redis reachable | Full: JWT + allowlist + blacklist all consistent |
| **Fully degraded** | Redis unreachable | Deterministic: each control follows its declared `fail_open` / `fail_closed` mode |
| **Transient** | Partial Redis failure (some commands succeed, others fail within the same request) | Non-deterministic: rate-limit increment may fail while allowlist read succeeds; outcomes become request-order dependent |

The transient regime is observable — it does not enable a specific exploit, but authorization consistency is weakened until Redis returns to a stable state. Observable via:

- `auth_redis_circuit_breaker_open` gauge → `1` means the circuit is open (full degradation)
- `auth_degraded_decision_total` counter → increments on every per-control degraded decision
- `/health/` `circuit_breaker` field → `"open"` | `"closed"`

The asymmetric posture (refresh + session writes fail-closed; rate limit + access revocation fail-open) is intentional: the highest-value targets for an attacker (token replay, unrevoked sessions) are hard-rejected; availability controls are preserved.

API key rate limiting: when Redis is unavailable, strict deployments return 503 rather than admit a valid key with no rate-limit ceiling. Strict behaviour is inherited from any production/strict posture (`ENVIRONMENT=production`, `STRICT_PRODUCTION_MODE=true`, or `AUTH_STRICT_MODE=true`) and can also be forced anywhere with `API_KEY_STRICT_RATE_LIMIT=true`. Only non-production, non-strict development fails open, and that admission is logged as unsafe. Either path emits a `degraded_decision_total{control="api_key_rate_limit"}` sample; logs never contain the raw key.

### Database unavailable

All routes that touch the database return `503 Service Unavailable` with a clear message.

### Health endpoint

```http
GET {API_PREFIX}/health/
```

```json
{
  "status": "ok",
  "token_mode": "stateful",
  "effective_mode": "stateful",
  "redis": "ok",
  "circuit_breaker": "closed",
  "database": "ok",
  "revocation_available": true,
  "rate_limiting_available": true,
  "degraded_since": null,
  "degradation_modes": {
    "rate_limit": "fail_open",
    "refresh_validation": "fail_closed",
    "session_write": "fail_closed",
    "access_revocation": "fail_open"
  }
}
```

`circuit_breaker` is `"open"` when Redis is required but currently unavailable (requests are short-circuited), and `"closed"` when healthy or not required.

`degradation_modes` shows the effective per-control policy (respecting `AUTH_STRICT_MODE`). `degraded_since` is the UTC timestamp when Redis first became unreachable in the current process lifetime, or `null` when healthy.

---

## Deployment Modes

| Mode | `API_BIND_IP` | TLS | HSTS | Use when |
| ---- | ------------- | --- | ---- | -------- |
| **Development** | `0.0.0.0` | mkcert (trusted) or self-signed | off | local machine, Docker dev loop |
| **Private LAN / homelab** | `0.0.0.0` or `127.0.0.1` | local CA recommended | off | Raspberry Pi, NAS, private LAN |
| **Public / production** | `127.0.0.1` | valid cert required | on (opt-in) | VPS, cloud, internet-facing |

### Running behind a reverse proxy (real client IP)

Requires a coordinated three-layer setup:

1. **Traefik** — add `forwardedHeaders.trustedIPs` to each entrypoint in `traefik.yml` (strips client-supplied `X-Forwarded-For`, prevents IP spoofing).
2. **Uvicorn** — the startup script reads `TRUSTED_PROXY_IPS` (default `172.16.0.0/12`) and passes it via `--proxy-headers --forwarded-allow-ips`. Never use `*`.
3. **Application** — `_client_ip()` reads the leftmost `X-Forwarded-For` value, which is trustworthy only because layers 1 and 2 have been configured. Set `TRUSTED_PROXY_COUNT=0` in `auth.env` to bypass XFF entirely (no proxy in front of FastAPI).

### Content Security Policy and response headers (production only)

Hardening headers are applied at two complementary layers:

1. **Application layer (default)** — `auth-sdk-m8 ≥ 1.2.1` emits `X-Frame-Options` and
   `X-Content-Type-Options` in every environment, adds `Referrer-Policy` and
   `Permissions-Policy` whenever `ENVIRONMENT=production` or `STRICT_PRODUCTION_MODE=true`,
   and emits CSP/HSTS only when explicitly opted in (`CONTENT_SECURITY_POLICY_ENABLED` /
   `HSTS_ENABLED`, never on `local`). See
   [Response Security Headers](#response-security-headers) for the tiers and tunable settings.
   This works regardless of the proxy in front and is the recommended baseline.
2. **Edge layer (optional)** — each example stack also ships two Traefik configs in `traefik/`:

   | File | Purpose |
   | ---- | ------- |
   | `dynamic_conf.yml` | Development — no CSP, Swagger UI works |
   | `production_dynamic_conf.yml` | Production — adds `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and enables HSTS at the edge. Replace `dynamic_conf.yml` with this file when deploying publicly and update the `Host` rules to your FQDN. |

To avoid duplicate headers, pick one layer as the source of truth: either keep the app-level
layer (set `SECURITY_HEADERS_ENABLED=true`, default) and leave the dev Traefik config in place,
or disable the app layer (`SECURITY_HEADERS_ENABLED=false`) and enforce headers at Traefik via
`production_dynamic_conf.yml`. Verify with `curl -I` after deployment.

### HSTS (opt-in, public deployments only)

At the edge, `Strict-Transport-Security` is commented out in all `traefik/dynamic_conf.yml`
files and enabled by default in `production_dynamic_conf.yml`. At the application layer it is
**off by default** and emitted only when `HSTS_ENABLED=true` (and `HSTS_MAX_AGE > 0`); it is
never emitted on a `local` stack even when enabled. Only activate HSTS after confirming TLS is
stable and the hostname will remain HTTPS-only for the full max-age period.

---

## Security defaults

Security-critical settings and how they behave across the stack. All `secret_fields` reject the
literal `changethis` placeholder at startup — a service with any modeled secret still at its
placeholder fails closed immediately.

**Boot-required conditions** — the service refuses to start unless:

- Every `secret_fields` value has been changed from `changethis`.
- `EVENT_SIGNING_KEY` is set when `EVENT_SIGNING_ENABLED=true` (the default).
- `TOKEN_ISSUER` and `TOKEN_AUDIENCE` are set when `TOKEN_STRICT_VALIDATION=true` (the default).
- `ACCESS_PUBLIC_KEY_FILE` or `JWKS_URI` is present for RS256/ES256.

| Setting | SDK default | Dev / local | `hardened_m8` | Production overlay |
| --- | --- | --- | --- | --- |
| `ACCESS_TOKEN_ALGORITHM` | `RS256` | any | `RS256` | `RS256` |
| `TOKEN_STRICT_VALIDATION` | `true` | `true` | `true` | `true` |
| `TOKEN_ISSUER` | `None` | optional | set in `auth.env.example` | **required** (fatal if unset) |
| `TOKEN_AUDIENCE` | `None` | optional | set in `auth.env.example` | **required** (fatal if unset) |
| `EVENT_SIGNING_ENABLED` | `true` | `true` | `true` | `true` |
| `EVENT_SIGNING_KEY` | `None` | **required** — boot fails without it | non-`changethis` required | non-`changethis` required |
| `ENVIRONMENT` | `local` | `local` | `local` | `production` (overlay) |
| `STRICT_PRODUCTION_MODE` | `false` | `false` | `false` | `true` (overlay) |
| `ALLOWED_HOSTS` | `None` | no host check | `None` — Traefik `Host()` rules are primary | **required** (strict fatal if unset) |
| `ALLOWED_ORIGINS` | `["http://localhost:8080"]` | localhost | localhost | no `localhost` (prod fatal) |
| `SET_DOCS` / `SET_OPEN_API` | `true` | on | on | **off** (gated in production) |
| `HSTS_ENABLED` | `false` | never (local-blocked) | never | opt-in only (`HSTS_ENABLED=true`) |
| `CONTENT_SECURITY_POLICY_ENABLED` | `false` | never (local-blocked) | never | opt-in only |
| `SESSION_COOKIE_SECURE` | `false` | `false` | `false` | `true` (overlay) |
| `ALLOW_INTERNAL_HTTP` | `false` | no check in `local` | Docker-network-only | `true` opt-in (single trusted Docker host) |
| `AUTH_STRICT_MODE` | `false` | `false` | `false` | optionally `true` for fail-closed Redis ops |

**Dev-only stacks.** The examples below are development/learning templates and must not be used
as-is for production deployments:

| Stack | Why dev-only |
| --- | --- |
| `quickstart_m8` | HS256, no hardening layer, loopback DB/Redis |
| `postgres_m8` | No hardening layer, loopback DB |
| `rs256_m8` | RS256 demo, no hardening layer |
| `metrics_m8` | Observability demo, no hardening layer |
| `vault_dev_m8` | HashiCorp Vault in **dev mode** with root token — never production |

`hardened_m8` is the only stack with a production path — apply `docker-compose.production.yml` as
documented in [Going to production](#8-going-to-production-hardened_m8-overlay). See
[`examples/docker_compose/SECURITY.md`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/SECURITY.md)
for the full operational security runbook (trust model, route inventory, secret inventory, attacker
paths, production checklist, and incident response playbooks).

For the complete cross-layer table including fastapi-m8 consumer defaults, see the
[auth-sdk-m8 Defaults by layer](https://github.com/mano8/auth-sdk-m8#defaults-by-layer) section.

---

## API Key Authentication

API keys are created by authenticated users and validated by consumer services via the `GET /profile/api-keys/verify` endpoint (or the `get_current_api_key` FastAPI dependency in the SDK).

### Key lifecycle

- Created with `POST /profile/api-keys/` — plaintext key returned **once only**, never stored.
- Stored as a SHA-256 hash in the database alongside metadata (name, expiry, revocation flag).
- `last_used_at` is updated via a Redis write-behind queue flushed every 60 seconds.
- Revoked with `DELETE /profile/api-keys/{key_id}`.

### Rate limiting

Each key is checked against up to four fixed windows (MINUTE, HOUR, DAY, MONTH). Priority chain: per-key `RateLimit` rows → per-user defaults → `API_KEY_DEFAULT_LIMIT_*` settings.

Response headers on every API key request:

| Header | Description |
| ------ | ----------- |
| `X-RateLimit-Limit` | Limit for the tightest (MINUTE) window |
| `X-RateLimit-Remaining` | Remaining requests in the MINUTE window |
| `X-RateLimit-Reset` | Unix timestamp when the MINUTE window resets |
| `Retry-After` | Seconds to wait (429 responses only) |

---

## Private API

Endpoints under `/user/private/` are for inter-service calls only:

- Must not be exposed to the public internet — enforce at the reverse proxy / Docker network level.
- Every request must present a per-consumer credential — `X-Internal-Client: <consumer-id>` + `X-Internal-Token: <consumer-secret>` matching a `PRIVATE_API_CONSUMERS` entry (or a short-TTL `Authorization: Bearer <service-token>`), and carry the scope the route requires. The legacy shared `X-Internal-Token: <PRIVATE_API_SECRET>` gate was retired in v1.0.0.

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/private/users/` | Create a user account (called by other microservices) |
| POST | `/private/v1/jti-status` | Introspect an access-token JTI. A subject-bound **v2** request (`{jti, expected_user_id, schema_version: "2"}`) gets the database-authoritative revocation decision in `stateful` mode — active carries `{user_id, auth_generation}`, every inactive cause is one generic `{active: false}`, and an unreachable database is `503` (never fail-open). A legacy `{jti}`-only request keeps the v1 `{active}` behaviour. |
| GET | `/private/v1/events/stream` | SSE bridge — pushes `session-revoked` / `user-deleted` events to consumers (best-effort accelerator; `jti-status` remains the revocation authority) |
| POST | `/private/v1/service-token` | Exchange bootstrap credential for a short-TTL service token (scoped to granted scopes) |

### Bootstrap and rotation runbook

#### Generating `PRIVATE_API_CONSUMERS`

Each consumer gets a unique client ID and a strong secret. Generate one
per consumer and build the JSON map:

```bash
# Generate a strong secret per consumer (32+ bytes, URL-safe base64).
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

The consumers map is a JSON object keyed by consumer ID. Scopes are
deny-by-default: list only the scopes the consumer actually needs.

```json
{
  "media-service": {
    "secret": "<generated-secret>",
    "scopes": ["introspection", "event-stream"]
  },
  "worker-service": {
    "secret": "<generated-secret>",
    "scopes": ["user-create"]
  }
}
```

Store the map as a Docker secret and reference it via
`PRIVATE_API_CONSUMERS_FILE` (preferred) or inline via `PRIVATE_API_CONSUMERS`:

```ini
# docker-compose hardened: mount as a Docker secret
PRIVATE_API_CONSUMERS_FILE=/run/secrets/private_api_consumers.json
```

```yaml
# docker-compose.yml
secrets:
  private_api_consumers:
    file: ./secrets/private_api_consumers.json
services:
  auth_user_service:
    secrets:
      - private_api_consumers
```

Each consumer sets its own side of the credential — the client ID must
match a key in the issuer's `PRIVATE_API_CONSUMERS` map:

```ini
# consumer env (api.env / media.env)
INTERNAL_CLIENT_ID=media-service
PRIVATE_API_SECRET=<the secret for media-service in PRIVATE_API_CONSUMERS>
```

#### Rotating a consumer secret

Rolling rotation (no downtime):

1. Add a `<consumer-id>-new` entry to the issuer's `PRIVATE_API_CONSUMERS`
   with the new secret and the same scopes.
2. Reload the issuer (signal `SIGHUP` or restart). Both entries are now
   valid.
3. Update the consumer's `PRIVATE_API_SECRET` to the new secret and restart
   the consumer.
4. Remove the old `<consumer-id>` entry from `PRIVATE_API_CONSUMERS` and
   reload the issuer again.

If the consumer uses the service-token exchange (`/private/v1/service-token`),
its short-TTL tokens expire within `SERVICE_TOKEN_TTL_SECONDS` (default 300 s)
after the bootstrap credential is revoked — no additional invalidation step is
needed.

#### Emergency rotation for a stolen service token

A stolen short-TTL service token expires naturally within
`SERVICE_TOKEN_TTL_SECONDS`. To force-invalidate before expiry:

1. Immediately rotate the consumer's bootstrap secret (see above) — the
   issuer will reject all new token exchanges from the compromised credential.
2. Restart the affected consumer service so it re-exchanges for a new token.
3. If the stolen token's `jti` is known, add it to the JTI blacklist via
   the internal session-revocation path (requires a superuser call to
   `DELETE /sessions/delete/{session_id}/`).

For a stolen bootstrap credential (`X-Internal-Token`), rotate immediately:
remove the old entry from `PRIVATE_API_CONSUMERS`, reload the issuer, then
add the new entry. The issuer rejects the old credential the moment the
registry is updated.

#### Verification with `security-tests-m8`

After any rotation or environment change, run the private API live suite to
confirm the issuer accepts the new credential and rejects the old one:

```bash
# Inside the security-tests-m8 repo
LIVE_TEST_PRIVATE_API_CLIENT_ID=media-service \
LIVE_TEST_PRIVATE_API_SECRET=<new-secret> \
AUTH_BASE_URL=http://auth-service:8000 \
pytest tests/live/test_private_api_live.py -v
```

The suite covers:

- Bootstrap credential acceptance (`X-Internal-Client` + `X-Internal-Token`).
- Service-token exchange and scoped endpoint access.
- Legacy `X-Internal-Token`-only shape rejected (no `X-Internal-Client`).
- Revocation check via `POST /private/v1/jti-status`.

---

## Consumer Service Integration

`examples/fastapi_full` and `examples/fastapi_minimal` are reference implementations showing how a downstream microservice integrates with `auth_user_service` using [fastapi-m8](https://github.com/mano8/fastapi-m8) and [auth-sdk-m8](https://github.com/mano8/auth-sdk-m8). `fastapi_full` demonstrates DB session, health checks, auth deps, and lifespan teardown; `fastapi_minimal` is the minimal three-step setup.

[fastapi-m8](https://github.com/mano8/fastapi-m8) is the recommended consumer integration package — it wires CORS, health, lifespan, and auth dependencies in a few lines and bundles `auth-sdk-m8` for JWT validation and shared schemas:

```bash
pip install fastapi-m8 --upgrade                        # minimal consumer
pip install "fastapi-m8[db,postgres,mysql]" --upgrade   # with SQLModel + DB drivers (fastapi_full)
```

### Minimal integration

```python
# core/deps.py
from fastapi_m8 import AuthDeps, build_auth_deps
from .config import settings

auth: AuthDeps = build_auth_deps(settings)
CurrentUser = auth.CurrentUser
```

```python
# main.py
from fastapi_m8 import AppLifecycle, create_app
from .core.deps import auth

app = create_app(settings, api_router, service_name="my-service", service_version="1.0.0",
                 lifecycle=AppLifecycle(auth_deps=auth))
```

`build_auth_deps` reads `ACCESS_TOKEN_ALGORITHM`, `ACCESS_SECRET_KEY` / `ACCESS_PUBLIC_KEY_FILE`, `TOKEN_ISSUER`, `TOKEN_AUDIENCE`, `JWKS_URI`, `TOKEN_MODE`, `INTROSPECTION_URL`, and failure-mode settings directly from a `ConsumerServiceSettings` instance.

### JWKS-based key validation (RS256/ES256)

When `JWKS_URI` is set, `build_auth_deps` wires up `JwksKeyResolver` automatically. The resolver fetches `/.well-known/jwks.json`, caches keys by `kid`, and refreshes on cache miss — supporting zero-downtime key rotation.

```ini
ACCESS_TOKEN_ALGORITHM=RS256
JWKS_URI=http://auth-service/user/.well-known/jwks.json
JWKS_CACHE_TTL_SECONDS=300
```

### Revocation check (stateful mode)

Consumer services check revocation via an HTTP call to the auth service private API —
auth Redis is never shared with consumers. Set `INTROSPECTION_URL`, `INTERNAL_CLIENT_ID`, and
`PRIVATE_API_SECRET` (the consumer's per-consumer bootstrap secret) when `TOKEN_MODE=stateful`. The
client id + secret must match an entry in the auth service `PRIVATE_API_CONSUMERS` map (the legacy
shared-secret gate was retired in v1.0.0):

```ini
INTROSPECTION_URL=http://auth_user_service:8000/user/private/v1/jti-status
INTERNAL_CLIENT_ID=example-api
PRIVATE_API_SECRET=<this consumer's secret, matching its PRIVATE_API_CONSUMERS entry>
```

`fastapi-m8`'s `build_auth_deps` wires `RemoteRevocationClient` automatically and honours
`ACCESS_REVOCATION_FAILURE_MODE` from the consumer's settings. The **default is `fail_closed`**
— any outage returns HTTP 503 rather than accepting a potentially-revoked token. Set
`ACCESS_REVOCATION_FAILURE_MODE=fail_open` in `api.env` to restore availability-first behaviour,
or `AUTH_STRICT_MODE=true` to force all failure-mode controls closed. For a legacy v1
(`{jti}`-only) request the issuer's `/private/v1/jti-status` endpoint mirrors the same
setting: Redis-unavailable returns `active=false` when `fail_closed` is effective. The
subject-bound **v2** decision is database-authoritative instead — the Redis blacklist is only
an accelerator, so a Redis outage falls back to the DB result, and only an unreachable
authoritative database returns `503`; `ACCESS_REVOCATION_FAILURE_MODE=fail_open` is **not**
honoured for that generation decision.

### Issuer / audience enforcement (secure-by-default)

`auth-sdk-m8 ≥ 1.0.0` enables `TOKEN_STRICT_VALIDATION` by default. Set `TOKEN_ISSUER` and `TOKEN_AUDIENCE` to the **same values** in both the auth service and every consumer: the auth service embeds `iss`/`aud` claims in issued tokens and all validators require an exact match. Under the strict default the service **fails closed at boot** until both are set. Opt out for legacy/local deployments with `TOKEN_STRICT_VALIDATION=false`, which enforces `iss`/`aud` only when configured.

### Event signing and auth Redis isolation

**`EVENT_SIGNING_KEY` is required at boot** (auth-sdk-m8 ≥ 1.0.0 secure-by-default, F3) unless `EVENT_SIGNING_ENABLED=false`. Set it in `auth_user_service/.env` and in every consumer stack's env file before starting any service. The dev placeholder (`DEV-ONLY-do-not-use-event-signing-key-Aa1!`) shipped in example env files must be replaced with a secrets-managed value in staging and production.

**Auth Redis is sensitive and fa-auth-only.** The session/JTI blacklist Redis instance is private to this service. Consumer services check revocation via the HTTP private API (`POST /private/v1/jti-status`) — they never connect to auth Redis directly. This boundary is already enforced architecturally (see [Revocation check](#revocation-check-stateful-mode) above).

**The SSE bridge (`GET /private/v1/events/stream`) is live.** Consumers that opt in to low-latency cache eviction can connect to the stream using `AuthEventStreamClient` from `auth-sdk-m8 ≥ 1.2.0` — it reconnects with jitter, replays buffered events via `Last-Event-ID`, verifies each payload's HMAC signature, and calls `on_gap()` so the consumer can flush its local caches when the buffer is unresumable. The bridge is a best-effort accelerator; `POST /private/v1/jti-status` remains the revocation authority. Consumers that do not connect continue to work correctly.

---

## Development

### Run locally (without Docker)

```bash
cd auth_user_service
pip install -r requirements_base.txt -r requirements_dev.txt
uvicorn auth_user_service.main:app --host 0.0.0.0 --port 8000 --reload
```

### VS Code remote debugging

Set `VSCODE_DEBUG=true` in the container environment. The startup script launches `debugpy` on port `5678` and waits for the debugger to attach before starting Uvicorn.

### Database migrations

Migrations are applied automatically on container start. To run manually:

```bash
alembic -c auth_user_service/alembic.ini revision --autogenerate -m "description"
alembic -c auth_user_service/alembic.ini upgrade head
```

### Linting & formatting

```bash
ruff format .
ruff check .
ruff check . --fix
```

### Type checking

```bash
mypy auth_user_service --ignore-missing-imports
mypy examples/fastapi_full --ignore-missing-imports
```

### Security scan

```bash
bandit -r auth_user_service examples/fastapi_full --severity-level medium
```

### Tests

```bash
# Unit + integration tests (default — no live stack required)
pytest

# All live tests against a running stack
pytest -m live --no-cov

# Target a specific algorithm or token mode
pytest tests/live/test_security_universal.py --no-cov   # any stack
pytest -m live_asymmetric --no-cov                      # RS256 / ES256 stacks
pytest -m live_hs256 --no-cov                           # HS256 stacks
pytest -m live_stateful --no-cov                        # TOKEN_MODE=stateful
pytest -m live_hybrid --no-cov                          # TOKEN_MODE=hybrid
pytest -m live_stateless --no-cov                       # TOKEN_MODE=stateless
```

The live suite is modular — each file carries a `require_algorithm` / `require_token_mode` mark so tests are automatically skipped when the running stack does not match. `conftest.py` auto-detects the stack's algorithm, token mode, and Redis availability at session start. Tests decorated with `require_redis`, as well as all `live_stateful` and `live_hybrid` tests, are automatically skipped when the `/health/` endpoint reports `redis=unavailable`.

| Module | Mark | Covers |
| ------ | ---- | ------- |
| `test_security_universal.py` | `live_security` | 13 attack categories (A–M): brute-force, JWT forgery, IDOR, rate-limit bypass, CORS, private API exposure, file upload, info disclosure, HTTP headers, cookie security, API key abuse |
| `test_asymmetric.py` | `live_asymmetric` | alg=none confusion, JWKS exposure, attacker-generated key — RS256 / ES256 only |
| `test_hs256.py` | `live_hs256` | HS256-specific attacks |
| `test_stateful.py` | `live_stateful` | Token revocation, session-chain invalidation |
| `test_hybrid.py` | `live_hybrid` | Partial-Redis degraded mode behaviour |
| `test_stateless.py` | `live_stateless` | No-Redis guarantees |

The `tests/security/` unit suite (no live stack required) covers JWT security, Redis resilience, refresh lifecycle, refresh key-rotation fallback (`REFRESH_SECRET_KEY_OLD`), input sanitisation, JWKS endpoint, OAuth adversarial, iss/aud validation, session-chain invalidation, exception handling, and client IP attribution.

---

## Prometheus Metrics

Enabled with `METRICS_ENABLED=true`. The metric prefix is derived from `API_PREFIX` (e.g. `/user` → `user_`).

| Group | Metric | Type | Labels |
| ----- | ------ | ---- | ------ |
| traffic | `{prefix}http_requests_total` | Counter | method, endpoint, status_code |
| performance | `{prefix}http_request_duration_seconds` | Histogram | method, endpoint |
| reliability | `{prefix}http_errors_total` | Counter | method, endpoint, status_class |
| health | `{prefix}http_status_total` | Counter | status_code |
| auth | `{prefix}auth_login_attempts_total` | Counter | result: success \| wrong_credentials \| inactive_user \| rate_limited |
| auth | `{prefix}auth_token_refresh_total` | Counter | result: success \| invalid \| revoked \| rate_limited |
| auth | `{prefix}auth_logout_total` | Counter | — |
| auth | `{prefix}auth_token_validation_failures_total` | Counter | reason: invalid \| revoked \| inactive |
| auth | `{prefix}auth_oauth_attempts_total` | Counter | provider, result: success \| failed |
| auth | `{prefix}auth_revocation_failure_total` | Counter | operation: access_blacklist \| refresh_allowlist \| db_session |
| auth | `{prefix}auth_degraded_decision_total` | Counter | control: rate_limit \| refresh_validation \| session_write \| access_revocation; mode: fail_open \| fail_closed; reason: redis_unavailable \| revocation_failed |
| auth | `{prefix}auth_redis_circuit_breaker_open` | Gauge | 1 = Redis unavailable (circuit open), 0 = Redis healthy (circuit closed) |
| auth | `{prefix}auth_degradation_mode_active` | Gauge | control × mode label pair; value always 1 for active mode; set at startup |
| auth | `{prefix}auth_session_integrity_denial_total` | Counter | trigger: reuse_detected |
| auth | `{prefix}auth_api_key_validations_total` | Counter | result: success \| invalid \| revoked \| expired |
| auth | `{prefix}auth_api_key_rate_limit_checks_total` | Counter | result: checked \| allowed \| blocked |
| auth | `{prefix}auth_api_key_rate_limit_hits_total` | Counter | period: minute \| hour \| day \| month |
| auth | `{prefix}auth_api_key_lifecycle_total` | Counter | action: created \| revoked |
| auth | `{prefix}auth_api_key_flush_duration_seconds` | Histogram | — |

Alert rules for `metrics_m8` and `vault_dev_m8` stacks (`prometheus/alerts.yml`):

- `ApiKeyBlockRatioHigh` — hits/checks > 10% over 5 min
- `ApiKeyRateLimitInvariantViolation` — hits > checks × 1.1 (instrumentation sanity guard)
- `ApiKeyFlushLatencyHigh` — p99 flush latency > 500 ms
- `ApiKeyHighInvalidRate` — > 1 invalid/revoked/expired key/s over 5 min

---

## Dependencies

**Stack:** Python 3.14 · FastAPI · SQLModel · Redis · MariaDB / PostgreSQL 16 · Traefik · Docker Compose · Prometheus · Grafana

- [FastAPI](https://fastapi.tiangolo.com/)
- [SQLModel](https://sqlmodel.tiangolo.com/) + [Alembic](https://alembic.sqlalchemy.org/)
- [fastapi-m8](https://github.com/mano8/fastapi-m8) — consumer service integration (CORS, health, auth deps, lifespan); consumer services install this
- [auth-sdk-m8](https://github.com/mano8/auth-sdk-m8) — shared schemas, JWT validation, refresh token rotation, JWKS resolver, base controllers; bundled by `fastapi-m8`, also used directly by the auth service
- [Redis](https://redis.io/) — session revocation, refresh token allowlist, rate limiting, PKCE store, write-behind queue
- [PyJWT](https://pyjwt.readthedocs.io/) + [passlib](https://passlib.readthedocs.io/) + [cryptography](https://cryptography.io/)
- [google-auth](https://google-auth.readthedocs.io/) — Google OAuth2

### Reproducible release builds

Release (non-development) Docker images do **not** resolve the loose lower-bound
ranges in `requirements_base.txt` / `requirements_prod.txt` at build time. They
install from `auth_user_service/requirements_prod.lock` — a fully pinned,
`sha256`-hashed lock — with `pip install --require-hashes`. This guarantees that
rebuilding the same source cannot silently pull a different dependency graph, and
that the published SBOM describes exactly what shipped.

- The loose ranges remain the source of truth for *what* the service depends on.
- The lock is the pinned, hashed *resolution* of those ranges for release images.
- All packages (including the internal `auth-sdk-m8`) resolve from public PyPI
  only — the lock carries no custom index URL.

Regenerate the lock whenever a range in `requirements_base.txt` or
`requirements_prod.txt` changes, then re-run the audit gate:

```bash
cd auth_user_service
pip-compile --generate-hashes --no-emit-index-url \
    --output-file=requirements_prod.lock requirements_prod.txt
pip-audit -r requirements_prod.lock          # must report no known vulnerabilities
```

The lock, the Dockerfile `--require-hashes` install, and the
"SBOM reflects the locked environment" invariant are enforced by
`tests/security/test_dependency_lock.py`.

---

## License

Apache2 © Eli Serra
