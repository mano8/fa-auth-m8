# Shared live security test (hardened_m8 reference)

This example runs the full `security-tests-m8` live security suite against the `fa-auth-m8` hardened Docker Compose stack.

> **Reusable, not hardened-only.** This is the *shared* live test: the same
> folder runs against **any compose stack that uses `fa-auth-m8` as the issuer
> and `fastapi-m8`-based consumers** (minimal, staging, or production). Only the
> configuration in `.env` changes — see
> [Adapting To Another Stack](#adapting-to-another-stack). `hardened_m8` is just
> the reference target documented below.

- Tested compose stack on GitHub: [`mano8/fa-auth-m8/examples/docker_compose/hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8)
- Local compose stack path: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`
- Local live-test example folder: `/workspace/fa-auth-m8/examples/docker_compose/shared_live_tests`
- Canonical package example: [`mano8/security-tests-m8/examples/hardened_m8_full_security`](https://github.com/mano8/security-tests-m8/tree/main/examples/hardened_m8_full_security)

It is built for the default hardened stack routes:

- auth service: `http://localhost:9000/user`
- downstream FastAPI service: `http://localhost:9000/fastapi`
- public HTTPS entrypoint: `https://localhost:4430`
- stack root and JWT keys: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`

The live tests require a dedicated test-only superuser. Do not use `FIRST_SUPERUSER` / `FIRST_SUPERUSER_PASSWORD` from `auth.env`; the package preflight refuses that by default.

CLI mode is recommended for normal users and excludes destructive tests by default. This local pytest example is for custom tests, extra marker selection, and local suite extension. The unknown-route information-disclosure test now lives in the package full suite and no longer needs to be copied into this folder.

## Why run live security tests

Unit and contract tests verify code in isolation. They cannot prove that a *running, fully wired* stack — auth issuer, downstream consumers, Traefik, Redis, JWT keys — actually rejects a forged token, an `alg=none` JWT, an HS256 token signed with the public key, an unauthenticated call to a protected route, or a privilege-escalation attempt. Those failures only surface end-to-end. `security-tests-m8` drives the live HTTP surface the way an attacker would and asserts the stack fails closed. It covers the OWASP API Top 10 categories plus M8-specific JWT/JWKS/cross-service checks.

**When to run it:**

- After first bringing a stack up (`docker compose up -d`), as an acceptance gate.
- After any change to auth/token configuration (`TOKEN_MODE`, algorithm, issuer/audience, key rotation).
- After changing network exposure, Traefik routing, or upgrading a service image.
- In CI against an ephemeral stack, before promoting a build.

## Two ways to run it

| | CLI mode (recommended) | This pytest example |
| --- | --- | --- |
| Who | Operators / normal users | Authors of custom or extra tests |
| Where | From the **compose stack directory** | From **this folder** |
| Config | `test.env` in the stack dir | `.env` in this folder |
| Command | `security-tests-m8 run --env-file test.env` | `pytest` |
| Destructive tests | Excluded unless `--include-destructive` | Selected via markers |

CLI mode needs nothing from this folder — you install the package and point it at a stack's `test.env`. Use **this folder** only when you want to add local tests, select specific markers, or extend the suite. Both share the same underlying package, so coverage is identical for the checks that apply to your stack.

## What It Runs

The example includes:

- universal auth security suites
- stateful/stateless/hybrid contract suites
- RS256/JWKS/cross-service JWT suites
- HS256 rejection and weak-key suites
- protected endpoint checks for `/fastapi/category/` and `/fastapi/dashboard/users/activity/`

The hardened stack is RS256 and stateful, so pytest automatically skips suites that do not apply to that detected stack.

## Files

```text
examples/docker_compose/shared_live_tests/
├── env.example
├── pytest.ini
├── README.md
└── tests/live/
    ├── conftest.py
    └── test_full_security.py
```

## Start The Hardened Stack

From the hardened stack directory:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/hardened_m8
cp .env.example .env
cp auth.env.example auth.env
cp api.env.example api.env
cp test.env.example test.env   # live-test runner config (edit before running tests)
bash init.sh
docker compose up -d
```

`test.env` is not needed to boot the stack — it configures the `security-tests-m8`
run below. Copy it now so everything is in place, then edit it (dedicated test
superuser, opt-in secrets) before you run the suite.

### Dedicated test superuser

The suite needs superuser credentials because it exercises admin-only paths — creating users, listing accounts, deleting other users, issuing API keys. You must give it a **dedicated, test-only superuser**, not your real admin and not the stack's bootstrap `FIRST_SUPERUSER`:

- The preflight **refuses** to run as `FIRST_SUPERUSER` (`LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER=true`). Reusing the bootstrap account risks locking out or corrupting the identity your stack depends on.
- During a run the suite also creates one throwaway `redteam_*@redteam-test.com` regular user to attempt privilege escalation. The suite **deletes that user automatically at the end of the test session** (best-effort, through the admin account), so a run leaves no standing test identity behind.

Create the dedicated account first (it must already exist in the auth stack and have superuser permissions), then point the live-test env file at it:

```ini
LIVE_TEST_ADMIN_EMAIL=tester@example.com
LIVE_TEST_ADMIN_PASSWORD=change-this-test-password
```

**Clean up afterward.** The suite **auto-deletes** the throwaway `redteam_*@redteam-test.com` user it creates, at session teardown via the admin account. This is best-effort: a `redteam_*` account only survives if the stack was unreachable during teardown, so prune any leftovers by filtering on the `redteam_*@redteam-test.com` pattern. The suite does **not** delete the dedicated superuser — that account is pre-existing and yours to manage. Leaving standing superuser credentials on a stack is itself a security risk, so after a run delete or disable the dedicated test superuser, especially on any shared or long-lived deployment. On a throwaway/CI stack you tear down immediately, this is moot.

## Run With The Recommended CLI Mode

Install (or update to the latest release of) `security-tests-m8`:

```bash
pip install --upgrade security-tests-m8
```

From the hardened stack directory, keep stack configuration in `.env`, `auth.env`, `api.env`, `media.env`, and `grafana/.env`, then create a dedicated `test.env` for the live-test runner values:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/hardened_m8
cp test.env.example test.env
# Edit test.env with the dedicated test account and, if used, real opt-in secrets.
security-tests-m8 preflight --deployment-root .
security-tests-m8 run --env-file test.env
# Optional full mutation-heavy run:
security-tests-m8 run --env-file test.env --include-destructive
```

Deployment preflight scans non-example `*.env` files under the deployment root, including `test.env` if you keep it there. Do not leave `changethis` or other placeholder values in `test.env`; either replace the opt-in secret values with the real values from `auth.env` / `api.env`, or omit those variables to skip their opt-in checks.

## Run This Advanced Pytest Example

Use this folder when you want local pytest customization, marker selection, or extra local tests layered on top of the reusable package suite.

Copy the example env file, edit the dedicated test credentials, then run pytest from this directory. `tests/live/conftest.py` calls `configure_from_env()`, so the package loads `.env` from the current directory automatically:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/shared_live_tests
cp env.example .env
pytest
```

Useful marker selections:

```bash
pytest -m live
pytest -m "live and not destructive"
pytest -m live_asymmetric
pytest -m live_stateful
```

## Configuration Values

The example defaults are defined in `tests/live/conftest.py` and can be overridden with environment variables.

| Variable | Example value |
| --- | --- |
| `LIVE_TEST_AUTH_BASE` | `http://localhost:9000/user` |
| `LIVE_TEST_INTERNAL_AUTH_BASE` | `http://localhost:9000/user` (internal entrypoint exposing `/private/*`; F06 targets it) |
| `LIVE_TEST_SVC_BASE` | `http://localhost:9000/fastapi` |
| `LIVE_TEST_ADMIN_EMAIL` | `tester@example.com` |
| `LIVE_TEST_ADMIN_PASSWORD` | `change-this-test-password` |
| `LIVE_TEST_PUBLIC_BASE` | `https://localhost:4430` |
| `LIVE_TEST_PUBLIC_TLS_VERIFY` | `false` |
| `LIVE_TEST_PRIVATE_API_SECRET` | real `PRIVATE_API_SECRET`, or unset |
| `LIVE_TEST_PRIVATE_API_CLIENT_ID` | issuer consumer id (`example-api`) — `X-Internal-Client` for fa-auth-m8 ≥ 1.0.0; enables the F06 legacy-detection check |
| `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` | real `HEALTH_DETAIL_CREDENTIAL` (unlocks deep `/health` detail), or unset |
| `LIVE_TEST_REFRESH_SECRET_KEY` | real `REFRESH_SECRET_KEY`, or unset |
| `LIVE_TEST_FAIL_FAST_PREFLIGHT` | `true` |
| `LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER` | `true` |
| `LIVE_TEST_PROTECTED_ENDPOINTS` | `{"fastapi":["/category/","/dashboard/users/activity/"]}` |
| `LIVE_TEST_REPO_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` |
| `LIVE_TEST_DEPLOYMENT_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` |

`LIVE_TEST_REPO_ROOT` lets asymmetric-key tests inspect the hardened stack's generated `keys/private.pem` and `keys/public.pem` files.
`LIVE_TEST_PRIVATE_API_SECRET` and `LIVE_TEST_REFRESH_SECRET_KEY` are opt-in secret-exposure checks. If they are unset, those specific tests skip.
`LIVE_TEST_PRIVATE_API_CLIENT_ID` is the issuer's consumer id (`example-api` here) sent as `X-Internal-Client`; the hardened/quickstart/postgres/metrics/vault stacks now run a per-consumer issuer (`fa-auth-m8:1.0.0`, `PRIVATE_API_CONSUMERS` active), so set it together with `LIVE_TEST_PRIVATE_API_SECRET` to enable the F06 legacy-detection check (token-only must be rejected `401`).
`LIVE_TEST_INTERNAL_AUTH_BASE` is the internal service-to-service entrypoint that exposes `/private/*`. Hardened stacks block `/private` at the public edge (Traefik → 404), so the F06 legacy-shape rejection can only be observed on the internal entrypoint. Set it when `LIVE_TEST_AUTH_BASE` points at the public edge (e.g. `https://localhost:4430/user`); it falls back to `LIVE_TEST_AUTH_BASE` when unset.
`LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` unlocks the deep `/health` detail (token mode, Redis/DB). fa-auth-m8 ≥ 1.0.0 gates it on a dedicated credential decoupled from `PRIVATE_API_SECRET` (opt-in/fail-closed; must differ from it); set it to the stack's `HEALTH_DETAIL_CREDENTIAL` once enabled in `auth.env`. Without it, `require_redis` and `require_token_mode` suites skip with an explicit reason instead of running blind on defaults.

## Adapting To Another Stack

Nothing in this folder is specific to `hardened_m8` beyond the values in `.env`.
To target a different `fa-auth-m8` + `fastapi-m8` stack, copy `env.example` to
`.env` and change configuration only:

1. **Auth URL** — `LIVE_TEST_AUTH_BASE` → your issuer's public base.
2. **Service URL(s)** — `LIVE_TEST_SVC_BASE` (single) or `LIVE_TEST_SVC_BASES`
   with `LIVE_TEST_DEFAULT_SVC` (named map) → your `fastapi-m8` consumers.
3. **Protected endpoints** — `LIVE_TEST_PROTECTED_ENDPOINTS` → the real read
   endpoints of each service.
4. **Public entrypoint / TLS** — `LIVE_TEST_PUBLIC_BASE`, and
   `LIVE_TEST_PUBLIC_TLS_VERIFY=false` (or a CA bundle path) for self-signed
   local certs; leave verification on for a real CA.
5. **Roots** — `LIVE_TEST_DEPLOYMENT_ROOT` → the target compose directory;
   `LIVE_TEST_REPO_ROOT` → the stack holding the committed JWT keys (only needed
   for the asymmetric key-leak checks).

Algorithm-, token-mode-, and component-specific suites skip automatically when
they do not match the detected stack, so the same `.env` works across
HS256/RS256/ES256 and stateless/stateful/hybrid deployments without edits.
