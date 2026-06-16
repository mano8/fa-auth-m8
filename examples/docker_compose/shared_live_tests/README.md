# hardened_m8 full security test example

This example runs the full `security-tests-m8` live security suite against the `fa-auth-m8` hardened Docker Compose stack.

- Tested compose stack on GitHub: [`mano8/fa-auth-m8/examples/docker_compose/hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8)
- Local compose stack path: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`
- Example folder on GitHub: [`mano8/security-tests-m8/examples/hardened_m8_full_security`](https://github.com/mano8/security-tests-m8/tree/main/examples/hardened_m8_full_security)

It is built for the default hardened stack routes:

- auth service: `http://localhost:9000/user`
- downstream FastAPI service: `http://localhost:9000/fastapi`
- public HTTPS entrypoint: `https://localhost:4430`
- stack root and JWT keys: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`

The live tests require a dedicated test-only superuser. Do not use `FIRST_SUPERUSER` / `FIRST_SUPERUSER_PASSWORD` from `auth.env`; the package preflight refuses that by default.

CLI mode is recommended for normal users. This local pytest example is for custom tests, extra marker selection, and local suite extension. The unknown-route information-disclosure test now lives in the package full suite and no longer needs to be copied into this folder.

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
examples/hardened_m8_full_security/
├── .env.example
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
bash init.sh
docker compose up -d
```

Before running the live tests, create a dedicated superuser for the test suite and put that account in `shared_live_tests/.env`:

```ini
LIVE_TEST_ADMIN_EMAIL=tester@example.com
LIVE_TEST_ADMIN_PASSWORD=change-this-test-password
```

The account must already exist in the auth stack and must have superuser permissions.

## Run With The Recommended CLI Mode

Install `security-tests-m8` in editable mode:

```bash
cd /workspace/security-tests-m8
pip install -e .
```

From the hardened stack directory, keep stack configuration in `.env`, `auth.env`, `api.env`, `media.env`, and `grafana/.env`, then create a dedicated `test.env` for the live-test runner values:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/hardened_m8
security-tests-m8 preflight --deployment-root .
security-tests-m8 run --env-file test.env
```

## Run This Advanced Pytest Example

Use this folder when you want local pytest customization, marker selection, or extra local tests layered on top of the reusable package suite.

Copy the example env file, edit the dedicated test credentials, then run pytest from this directory. The package loads `.env` from the current directory automatically:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/shared_live_tests
cp .env.example .env
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
| `LIVE_TEST_SVC_BASE` | `http://localhost:9000/fastapi` |
| `LIVE_TEST_ADMIN_EMAIL` | `tester@example.com` |
| `LIVE_TEST_ADMIN_PASSWORD` | `change-this-test-password` |
| `LIVE_TEST_PUBLIC_BASE` | `https://localhost:4430` |
| `LIVE_TEST_PUBLIC_TLS_VERIFY` | `false` |
| `LIVE_TEST_PRIVATE_API_SECRET` | `changethis` |
| `LIVE_TEST_REFRESH_SECRET_KEY` | `changethis` |
| `LIVE_TEST_FAIL_FAST_PREFLIGHT` | `true` |
| `LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER` | `true` |
| `LIVE_TEST_PROTECTED_ENDPOINTS` | `{"fastapi":["/category/","/dashboard/users/activity/"]}` |
| `LIVE_TEST_REPO_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` |
| `LIVE_TEST_DEPLOYMENT_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` |

`LIVE_TEST_REPO_ROOT` lets asymmetric-key tests inspect the hardened stack's generated `keys/private.pem` and `keys/public.pem` files.
