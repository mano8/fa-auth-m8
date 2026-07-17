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
---

## Authority
All rules come from /.workspace/policy.index.json (type: python)

