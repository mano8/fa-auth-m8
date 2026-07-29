# fa-auth-m8

## Layer

Service (central authentication and authorization system).

## Role

Provide identity, token issuance, session management, and the private
authentication API for M8 consumer services. Consumers validate tokens locally
through `fastapi-m8` / `auth-sdk-m8`; only stateful revocation checks call this
service's private HTTP API.

## Service and security boundaries

- Own the authentication database schema, identity lifecycle, signing keys, and
  Redis state. Other services never access this database or Redis directly.
- Publish HTTP contracts, JWKS, and narrowly scoped private APIs; never add
  direct dependencies on another service's source or persistence layer.
- Reuse `auth-sdk-m8` for shared authentication primitives and keep consumer
  token validation compatible with the documented public contract.
- Keep browser-visible responses free of secrets, session material, signing
  keys, and internal operational details.

## Repository structure

- `auth_user_service/**` owns the FastAPI application, auth domain, schemas,
  migrations, and API routes.
- `examples/fastapi_minimal` is the compact `fastapi-m8` integration skeleton;
  `examples/fastapi_full` is the production-oriented consumer reference.
- `examples/docker_compose/**` owns deployable Compose examples and their
  stack-local documentation. Production hardening stays explicit in the
  corresponding overlays and environment templates.

## Example version alignment

The consumer examples in `examples/fastapi_minimal` and `examples/fastapi_full`
use the `fastapi-m8` consumer Python packages. When this repository version is
bumped, keep their versions aligned with the version in
`auth_user_service/__init__.py`.

## Repository commands

- `ruff format .`
- `ruff check .`
- `mypy auth_user_service --ignore-missing-imports`
- `bandit -r auth_user_service examples/fastapi_full --severity-level medium`
- `pytest`

## Standalone authority

This file, repository documentation, and existing CI are the authoritative local
context. A verified nearest workspace may optionally add launcher-selected
policies and tasks; its absence is a successful standalone condition and does not
make a parent workspace necessary.
