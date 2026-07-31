# fa-auth-m8

[![CI](https://github.com/mano8/fa-auth-m8/actions/workflows/CI.yaml/badge.svg)](https://github.com/mano8/fa-auth-m8/actions/workflows/CI.yaml)
[![Codacy](https://app.codacy.com/project/badge/Grade/edab51cc8805468fb3884e1d9e57ccdc)](https://app.codacy.com/gh/mano8/fa-auth-m8/dashboard)
[![codecov](https://codecov.io/gh/mano8/fa-auth-m8/graph/badge.svg?token=LH7GTT2JZY)](https://codecov.io/gh/mano8/fa-auth-m8)
[![Docker Pulls](https://img.shields.io/docker/pulls/tepochtli/fa-auth-m8)](https://hub.docker.com/r/tepochtli/fa-auth-m8)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/mano8/fa-auth-m8/blob/main/LICENSE)

**Self-hosted FastAPI authentication service for Docker Compose.**

`fa-auth-m8` gives Python microservice stacks a ready-to-run authentication
issuer: email/password login, Google OAuth2 with PKCE, JWT access and refresh
tokens, Redis-backed revocation, API keys, RBAC, Prometheus metrics, and
production-oriented Docker Compose examples.

Consumer services validate JWTs locally with
[fastapi-m8](https://github.com/mano8/fastapi-m8), which bundles
[auth-sdk-m8](https://github.com/mano8/auth-sdk-m8). In `stateful` mode,
consumers check revocation through the auth service private API instead of
connecting to auth Redis directly.

---

## Quick Start

```sh
git clone https://github.com/mano8/fa-auth-m8.git
cd fa-auth-m8/examples/docker_compose/quickstart_m8

cp auth.env.example auth.env
cp api.env.example api.env

# Replace every "changethis" value in auth.env and api.env, then:
bash init.sh
docker compose up --build
```

Open:

- Auth health: `http://localhost:9000/user/health/`
- Auth docs: `http://localhost:9000/user/docs`
- Example consumer docs: `http://localhost:9000/fastapi/docs`

The compose stacks run both services: `auth_user_service` as the authentication
issuer and `fastapi_full` as a ready-to-use protected FastAPI consumer service.

On Windows, run `init.sh` from Git Bash or WSL.

---

## What It Provides

### Authentication

- Email/password login with bcrypt password hashing
- Google OAuth2 login with PKCE
- JWT access and refresh token pair
- Refresh token stored in an `HttpOnly` cookie and rotated on every refresh
- Signing with `HS256`, `RS256`, or `ES256`
- JWKS endpoint for asymmetric key validation
- Token modes: `stateless`, `hybrid`, and `stateful`

### Security

- Secure-by-default issuer/audience validation for JWTs
- Redis-backed access-token revocation and refresh-token allowlists
- Login brute-force protection by email and source IP
- Refresh-token churn and reuse detection
- Per-consumer private API credentials via `PRIVATE_API_CONSUMERS`
- Short-lived scoped service tokens for private inter-service calls
- HMAC-signed auth event stream for low-latency consumer cache eviction
- Configurable fail-open or fail-closed Redis degradation controls
- Public health response that does not leak dependency state
- Optional hardened production overlay with read-only root filesystem,
  dropped Linux capabilities, resource limits, and network segmentation

### Application Features

- Role-based access control: `user`, `admin`, `superuser`
- User CRUD for superusers
- Profile self-service: read, update, password change, account deletion
- API key creation, verification, revocation, and per-key rate limits
- Dashboard activity endpoints
- Private user creation and token-introspection endpoints for internal services

### Operations

- Python 3.14 runtime image
- MariaDB or PostgreSQL, selected by configuration
- Redis for sessions, revocation, OAuth PKCE, rate limiting, and write-behind
  queues
- Alembic migrations applied automatically on container startup
- Prometheus metrics and Grafana dashboards in observability stacks
- HashiCorp Vault development stack and production Vault reference template
- Ready-to-use FastAPI consumer examples: `fastapi_full` and `fastapi_minimal`
- Live security-test harness examples for running-stack validation

---

## Docker Compose Stacks

Ready-to-run examples live under
[`examples/docker_compose/`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose).

| Stack | Database | Signing | Token mode | Best for |
| --- | --- | --- | --- | --- |
| [`quickstart_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/quickstart_m8) | MariaDB 12 | HS256 | `stateful` | Fast local start |
| [`postgres_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/postgres_m8) | PostgreSQL 18 | HS256 | `stateful` | PostgreSQL projects |
| [`rs256_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/rs256_m8) | MariaDB 12 | RS256 | `hybrid` | Asymmetric signing and JWKS |
| [`metrics_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/metrics_m8) | PostgreSQL 18 | HS256 | `stateful` | Prometheus and Grafana |
| [`hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8) | PostgreSQL 18 | RS256 | `stateful` | Production-capable hardened deployment |
| [`vault_dev_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/vault_dev_m8) | PostgreSQL 18 | RS256 | `stateful` | Learning Vault-based secret injection |

Production note: `quickstart_m8`, `postgres_m8`, `rs256_m8`, `metrics_m8`, and
`vault_dev_m8` are development or learning templates. Use `hardened_m8` with its
production overlay for an internet-facing deployment path.

---

## Ready-to-use FastAPI Examples

This repository includes two consumer services that show how application APIs
use `fa-auth-m8` without writing their own authentication layer.

| Example | What it shows | Use it when |
| --- | --- | --- |
| [`examples/fastapi_full`](https://github.com/mano8/fa-auth-m8/tree/main/examples/fastapi_full) | A full consumer service with `fastapi-m8`, DB session wiring, migrations, health checks, metrics, auth dependencies, lifespan cleanup, and protected routes | You want a practical starting point for a real microservice |
| [`examples/fastapi_minimal`](https://github.com/mano8/fa-auth-m8/tree/main/examples/fastapi_minimal) | The smallest protected FastAPI app: settings, `build_auth_deps`, `create_app`, and one authenticated `/hello/` route | You want to see the integration pattern in a few files |

Every Docker Compose stack includes `fastapi_full` behind Traefik at
`/fastapi`. After startup, open `http://localhost:9000/fastapi/docs` to try the
consumer API next to the auth API.

The minimal example is for copying the integration pattern into a new service:

```python
from fastapi_m8 import AppLifecycle, create_app

from .core.deps import auth

app = create_app(
    settings,
    api_router,
    service_name="example-minimal",
    service_version="1.0.0",
    lifecycle=AppLifecycle(auth_deps=auth),
)
```

---

## Token Modes

| Mode | Redis for JWT validation | Revocation behavior | Best for |
| --- | --- | --- | --- |
| `stateless` | No | No instant access-token revocation | Maximum scalability |
| `hybrid` | Refresh tokens only | Refresh tokens revoked immediately | Balanced default for asymmetric demos |
| `stateful` | Yes | Access and refresh tokens revoked immediately | Strongest session control |

Google OAuth requires Redis for PKCE exchange and is disabled in `stateless`
mode.

---

## Image Tags

```sh
docker pull tepochtli/fa-auth-m8:2.0.0
docker pull tepochtli/fa-auth-m8:latest
```

Use a pinned semver tag such as `2.0.0` for production. Avoid `latest` in
long-lived deployments.

To use the published image in your own compose stack:

```yaml
services:
  auth_user_service:
    image: tepochtli/fa-auth-m8:2.0.0
```

---

## Integrating a FastAPI Service

Install the consumer helper package:

```sh
pip install "fastapi-m8>=3.3.0,<4.0.0"
```

Minimal auth dependency setup:

```python
from fastapi_m8 import AuthDeps, build_auth_deps

from .config import settings

auth: AuthDeps = build_auth_deps(settings)
CurrentUser = auth.CurrentUser
```

For RS256 or ES256 deployments, consumers can validate tokens through the auth
service JWKS endpoint:

```ini
ACCESS_TOKEN_ALGORITHM=RS256
JWKS_URI=http://auth_user_service:8000/user/.well-known/jwks.json
JWKS_CACHE_TTL_SECONDS=300
```

For `stateful` mode, configure per-consumer private API credentials:

```ini
TOKEN_MODE=stateful
INTROSPECTION_URL=http://auth_user_service:8000/user/private/v1/jti-status
INTERNAL_CLIENT_ID=example-api
PRIVATE_API_SECRET=<the consumer secret configured in PRIVATE_API_CONSUMERS>
```

The auth service private API no longer accepts one global shared private-route
secret. Each consumer must be registered in `PRIVATE_API_CONSUMERS` with only the
scopes it needs.

---

## Main API Surface

All routes are served under `API_PREFIX`, which defaults to `/user`.

- `POST /login/access-token`
- `POST /login/refresh-token/`
- `POST /login/logout/`
- `GET /.well-known/jwks.json`
- `GET /profile/get/me/`
- `PATCH /profile/update/me/`
- `POST /profile/api-keys/`
- `GET /profile/api-keys/verify`
- `GET /users/`
- `GET /sessions/`
- `GET /health/`
- `GET /metrics`
- `POST /private/users/`
- `POST /private/v1/jti-status`
- `GET /private/v1/events/stream`
- `POST /private/v1/service-token`

See the full route table and environment reference in the
[repository README](https://github.com/mano8/fa-auth-m8).

---

## Useful Links

- Source: <https://github.com/mano8/fa-auth-m8>
- Docker image: <https://hub.docker.com/r/tepochtli/fa-auth-m8>
- Consumer framework: <https://github.com/mano8/fastapi-m8>
- Shared auth SDK: <https://github.com/mano8/auth-sdk-m8>
- Compose stack guide:
  <https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose>

---

## License

Apache-2.0
