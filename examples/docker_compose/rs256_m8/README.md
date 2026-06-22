# rs256_m8

**MariaDB 12** + **RS256 asymmetric token signing** + **hybrid** token mode. No monitoring services.

Access tokens are signed with a private RSA key (auth service only) and verified with the corresponding public key (consumer services). Consumers discover the public key automatically via the **JWKS endpoint** — no manual key distribution required.

**Choose this when:** you need asymmetric signing with JWKS support, but don't need Prometheus/Grafana dashboards. Use [hardened_m8](../hardened_m8/) for RS256 with metrics and container hardening, or [vault_dev_m8](../vault_dev_m8/) if you also need Vault.

---

## Summary

- [Architecture](#architecture)
- [Services](#services)
- [Limitations](#limitations)
- [How RS256 differs from HS256](#how-rs256-differs-from-hs256)
- [Setup](#setup)
- [How JWKS works](#how-jwks-works)
- [Token mode: hybrid](#token-mode-hybrid)
- [URLs](#urls)
- [Port map](#port-map)
- [Configuration reference](#configuration-reference)
- [Key rotation](#key-rotation)
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
       ├──► /user/*      → auth_user_service :8000  (RS256 issuer)
       └──► /fastapi/*   → fastapi_full :8000    (RS256 consumer via JWKS)
                │
       ┌────────┴────────┐
       ▼                 ▼
  m8_db (MariaDB 12)  redis_cache (Redis 8.8)
```

The auth service holds the **private key** and issues signed tokens. The fastapi service holds **no key** — it verifies tokens by fetching the public key from the JWKS endpoint.

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

- **No Prometheus / Grafana.** Use [hardened_m8](../hardened_m8/) for RS256+metrics or [metrics_m8](../metrics_m8/) for HS256+metrics.
- **No Vault.** The RSA private key is stored as a file mounted into the container. Use [vault_dev_m8](../vault_dev_m8/) for secrets-manager integration.
- **MariaDB only.** For PostgreSQL with RS256, use [hardened_m8](../hardened_m8/) or [vault_dev_m8](../vault_dev_m8/).

---

## How RS256 differs from HS256

| Aspect | HS256 (symmetric) | RS256 (asymmetric) |
| --- | --- | --- |
| Signing key | Shared secret (sign and verify) | Private key signs, public key verifies |
| Key distribution | Every service needs the secret | Consumers fetch the public key via JWKS |
| Key rotation | Requires coordinated secret update | Auth rotates private key; consumers auto-refresh |
| `kid` header in JWT | Not used | Stable identifier linking the JWT to a public key |
| `ACCESS_SECRET_KEY` | Required | **Not used** — omit it |

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

REFRESH_SECRET_KEY="<generate>"     # refresh tokens remain HS256 symmetric
DB_PASSWORD="<generate>"
DB_ROOT_PASSWORD="<generate>"
REDIS_PASSWORD="<generate>"
PRIVATE_API_SECRET="<generate>"
SESSION_SECRET="<generate>"  # session-cookie signing key, separate from TOKENS_ENCRYPTION_KEY
TOKENS_ENCRYPTION_KEY="<generate>"
EVENT_SIGNING_KEY="<generate>"  # HMAC key for auth event stream signing (boot fails closed without it)
```

Leave `ACCESS_KEY_ID=changethis_hex_kid` as-is — `init.sh` derives it automatically from the generated key fingerprint and writes the correct value.

`api.env` requires no changes. The `JWKS_URI` already points to the auth service's JWKS endpoint over the internal Docker network.

### 2. Generate RSA key pair + TLS certificates

```sh
bash init.sh
```

> **Windows:** use **Git Bash** or **WSL**.

This generates `keys/private.pem` and `keys/public.pem`, derives a stable `kid` from the DER fingerprint, writes `ACCESS_KEY_ID` into `auth.env`, and generates the self-signed TLS certificate for Traefik. Keep `keys/private.pem` out of version control (it is already in `.gitignore`).

### 3. Start

```sh
docker compose up --build
```

Migrations run automatically on first boot. The superuser defined in `auth.env` is created if it does not exist.

---

## How JWKS works

```text
Consumer receives JWT with header: {"alg": "RS256", "kid": "abc123"}
         │
         ▼
Is "abc123" in local cache?
   Yes → verify signature → done
   No  → GET http://auth_user_service:8000/user/.well-known/jwks.json
              │
              ▼  (returns public keys indexed by kid)
         Cache result for JWKS_CACHE_TTL_SECONDS (default: 300 s)
         Verify signature → done
```

- **No manual key sync** — consumers only need `JWKS_URI` pointing to the auth service.
- **Key rotation** — run `bash init.sh --rotate-keys`, restart the auth service, and consumers auto-refresh on the next unknown `kid`.

The JWKS endpoint (no auth required):

```text
http://localhost:9000/user/.well-known/jwks.json
```

---

## Token mode: hybrid

This stack uses `TOKEN_MODE=hybrid`:

| Mode | Access token validated by | Refresh token | Redis round-trip per request |
| --- | --- | --- | --- |
| `stateless` | JWT signature only | JWT signature only | No |
| **`hybrid`** | **JWT signature only** | **Redis allowlist** | **No** |
| `stateful` | JWT signature + Redis blacklist | Redis allowlist | Yes |

In `hybrid` mode, access tokens remain valid for their full lifetime after logout (no server-side blacklist). The refresh token is immediately invalidated. Use `TOKEN_MODE=stateful` if you need instant access token revocation.

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
| HTTPS | `https://localhost:4430/user/docs` (self-signed cert — accept browser warning) |

---

## Port map

| Port | Bound to | Purpose |
| --- | --- | --- |
| `8000` | `0.0.0.0` | Traefik HTTP |
| `4430` | `0.0.0.0` | Traefik HTTPS |
| `9000` | `127.0.0.1` | API services entry (set `API_BIND_IP` in `auth.env` to expose on LAN) |
| `8080` | `127.0.0.1` | Traefik dashboard |
| `3306` | `127.0.0.1` | MariaDB |
| `6379` | `127.0.0.1` | Redis |

---

## Configuration reference

### `auth.env` — auth service (issuer)

| Variable | Default | Notes |
| --- | --- | --- |
| `ACCESS_TOKEN_ALGORITHM` | `RS256` | Do not change to `HS256` here — use a different stack |
| `REFRESH_TOKEN_ALGORITHM` | `HS256` | Refresh tokens remain symmetric |
| `ACCESS_PRIVATE_KEY_FILE` | `/opt/keys/private.pem` | Path inside the container |
| `ACCESS_PUBLIC_KEY_FILE` | `/opt/keys/public.pem` | Path inside the container |
| `ACCESS_KEY_ID` | — | Stable `kid` written by `init.sh` |
| `REFRESH_SECRET_KEY` | — | HMAC secret for refresh tokens |
| `TOKEN_MODE` | `hybrid` | `stateless` / `hybrid` / `stateful` |
| `AUTH_SERVICE_ROLE` | `issuer` | Signs tokens with the RSA private key |
| `LOGIN_RATE_LIMIT_REQUESTS` | `5` | Max login attempts per window per email |
| `LOGIN_RATE_LIMIT_WINDOW_MINUTES` | `15` | Login rate-limit window in minutes |
| `REFRESH_RATE_LIMIT_REQUESTS` | `10` | Max refresh rotations per window per user |
| `REFRESH_RATE_LIMIT_WINDOW_MINUTES` | `5` | Refresh rate-limit window in minutes |
| `TRUSTED_PROXY_COUNT` | `1` | Trusted proxy hops for real client IP extraction. Set to `0` if no proxy. |
| `METRICS_ENABLED` | `false` | Set to `true` to expose `/user/metrics` |
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
| `AUTH_SERVICE_ROLE` | `consumer` — verifies tokens via JWKS, does not sign them |
| `JWKS_URI` | `http://auth_user_service:8000/user/.well-known/jwks.json` |
| `JWKS_CACHE_TTL_SECONDS` | `300` — how long to cache the public key before re-fetching |

---

## Key rotation

```sh
# 1. Regenerate the RSA key pair and update ACCESS_KEY_ID in auth.env
bash init.sh --rotate-keys

# 2. Restart the auth service (picks up new private key + kid)
docker compose up -d --build auth_user_service

# 3. Consumers self-update — no restart needed
```

Old tokens remain valid until they expire. After `JWKS_CACHE_TTL_SECONDS` the consumer cache refreshes; tokens with the old `kid` will then fail verification.

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
| `./db_data` | Persistent MariaDB data |
| `./redis/redis_data` | Persistent Redis snapshots |
| `./shared_migrations` | Alembic migration files (auto-created, shared between services) |
| `../../../auth_user_service` | Live source mount — Python changes apply without rebuild |

---

## Database isolation

This stack defaults to **Scenario 2** (per-service isolation). See the [database isolation guide](../README.md#database-isolation) for details and other scenarios.

---

## Common operations

```sh
# Start in background
docker compose up -d --build

# Verify JWKS endpoint is serving the public key
curl http://localhost:9000/user/.well-known/jwks.json | python -m json.tool

# Follow auth service logs
docker compose logs -f auth_user_service

# Full reset — stops containers and wipes the database
bash init.sh --reset-db
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
# Expected: {"status":"ok","token_mode":"hybrid","redis":"ok","database":"ok",...}

curl http://localhost:9000/user/.well-known/jwks.json
# Expected: {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"...","n":"...","e":"AQAB"}]}
```

---

## Production deployment

When deploying publicly, replace `traefik/dynamic_conf.yml` with `traefik/production_dynamic_conf.yml`. The production config:

- Ships `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Strict-Transport-Security` (HSTS) **commented out** in `security-headers-prod` — both are opt-in. Uncomment only after TLS is stable with a trusted certificate (and confirm the CSP does not break your frontend/docs). HSTS stays off by default because, once sent, browsers refuse plain HTTP to the host for the full `stsSeconds` even after you disable it.
- Dev `dynamic_conf.yml` has no CSP so Swagger UI works during development.

Also update the `Host` rules in the production config to match your actual FQDN.

---

## Troubleshooting

**Auth service fails to start — key file not found** — ensure you ran `bash init.sh` and that `keys/private.pem` and `keys/public.pem` both exist.

**JWKS endpoint returns empty `keys` array** — the service started before the key files were mounted. Restart: `docker compose restart auth_user_service`.

**Consumer rejects valid tokens** — confirm `ACCESS_KEY_ID` in `auth.env` matches the `kid` in your JWTs. Decode a token at `https://jwt.io` and compare the `kid` header.

**`changethis` rejection on startup** — replace all `changethis` values in `auth.env`. `ACCESS_SECRET_KEY` must be absent (not set) for RS256.

**Port conflict** — identify the conflicting process with `netstat -ano | findstr <PORT>` (Windows) or `lsof -i :<PORT>` (Mac/Linux).

---

> [Docker Compose examples](../README.md) · [Repository root](https://github.com/mano8/fa-auth-m8/tree/main)
