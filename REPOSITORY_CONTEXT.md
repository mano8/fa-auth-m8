# fa-auth-m8

## Layer

Service (authentication system).

## Purpose

Provide the central authentication service for all microservices.

## Responsibilities

- Authenticate users.
- Issue tokens.
- Validate sessions.

## Repository boundaries

- Own this service's database schema.
- Do not add direct dependencies on other services.
- Use `auth-sdk-m8` for shared authentication primitives.

## Example version alignment

The consumer examples in `examples/fastapi_minimal` and `examples/fastapi_full`
use the `fastapi-m8` consumer Python packages. When this repository version is
bumped, keep their versions aligned with the version in
`auth_user_service/__init__.py`.

## Standalone authority

This file, repository documentation, and existing CI are the authoritative local
context. A verified nearest workspace may optionally add launcher-selected
policies and tasks; its absence is a successful standalone condition and does not
make a parent workspace necessary.
