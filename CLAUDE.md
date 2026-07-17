# fa-auth-m8

## Layer
Service (authentication system)

---

## Purpose
Central authentication service for all microservices.

---

## Responsibilities
- user authentication
- token issuance
- session validation

---

## Rules
- Owns its database schema
- No direct dependency on other services
- Must use auth-sdk-m8 for shared primitives
- consummers examples are present on `/workspace/fa-auth-m8/examples` folder as `fastapi_minimal` and `fastapi_full` who use `fastapi-m8` consummer python packages. Those consummer examples versions must ever aligned on `/workspace/fa-auth-m8/auth_user_service/__init__.py` version on repo version bump.
---

## Authority
All rules come from /.workspace/policy.index.json (type: python)