# Layer B — database integration matrix (`TEST-DB-01`)

White-box validation of ORM mappings, repositories, SQL transactions, Alembic
migrations, constraints, locking, concurrency, and dialect compatibility against
**ephemeral real database containers**.

This layer is the authoritative acceptance evidence for database portability.
SQLite results never replace it: the unit suite may not certify migrations,
`SELECT ... FOR UPDATE`, `SKIP LOCKED`, isolation levels, engine-enforced
enum/`CHECK` semantics, triggers, foreign-key cascades, or concurrency.

## Certified engines

| `--database` | Pinned image | Migration chain used |
|---|---|---|
| `postgresql` | `postgres:18.4-alpine` | `examples/docker_compose/postgres_m8` |
| `mysql` | `mysql:8.4.10` | `examples/docker_compose/rs256_m8` |
| `mariadb` | `mariadb:12.3.2-ubi` | `examples/docker_compose/quickstart_m8` |

MySQL and MariaDB are **separate certified dialects**. They share the
`mysql+pymysql` driver family and therefore the same MySQL-flavoured migration
chain, but passing on one is never evidence for the other.

## Running it

The suite is excluded from the default `pytest` run (`pytest.ini` carries
`-m "not database_integration"`), so the unit gate stays Docker-free and its
100% coverage threshold is unaffected.

```bash
# Start a disposable container automatically (needs a Docker daemon):
pytest -m database_integration tests/integration/database --database=postgresql --no-cov
pytest -m database_integration tests/integration/database --database=mysql --no-cov
pytest -m database_integration tests/integration/database --database=mariadb --no-cov
```

Against an already-running instance (the CI service-container shape, and the
fastest way to iterate locally):

```bash
export FA_AUTH_IT_MODE=external
export FA_AUTH_IT_HOST=127.0.0.1 FA_AUTH_IT_PORT=5432
export FA_AUTH_IT_DATABASE=auth_it_db FA_AUTH_IT_USER=auth_it_user
export FA_AUTH_IT_PASSWORD='ItTestDb1!secure'
pytest -m database_integration tests/integration/database --database=postgresql --no-cov
```

`FA_AUTH_IT_DIALECT` is an environment equivalent of `--database` for runners
that cannot pass options.

> **The target must be disposable.** `test_migrations.py` drops and recreates
> the entire schema. Never point this suite at an example stack's working
> `auth_db`.

## What each module owns

| Module | Required coverage |
|---|---|
| `test_migrations.py` | `upgrade head` from empty; upgrade from **every** supported prior revision; ORM-metadata vs. migrated schema; Enforce failing and rolling back over un-repaired rows; the Expand → legacy-session-revocation → Enforce cutover (legacy sessions **revoked, never backfilled**); downgrade round trip |
| `test_constraints.py` | role/flag equivalence `CHECK` (both directions, separated from `NOT NULL`); native enum representation; `BIGINT auth_generation`; tombstone without FK; `api_key_audiences`/`RateLimit` cascades; `access_mode` default backfill; outbox uniqueness and indexes; seeded `security_policy` |
| `test_locking.py` | `security_policy` `SELECT ... FOR UPDATE` contention; outbox `SKIP LOCKED` claiming; both horizon-bounded purges batching under real contention |
| `test_concurrency.py` | two-connection last-superuser race; concurrent-login-during-downgrade generation race; concurrent role changes; rollback after partial failure |
| `test_revocation_persistence.py` | database persistence for every 3.5.4 revocation path, each re-proven **with Redis unavailable** through the real v2 JTI-status route |
| `test_audit_and_purge.py` | the audit table's schema-level write-once/no-targeted-delete guards, and both retention purges (floor, horizon, batching, maintenance-row survival) |

## CI policy

`.github/workflows/database-integration.yaml` runs the matrix on every
database-sensitive pull request (path-filtered) and in full on main, nightly,
and release. **`Database integration matrix` is the single stable required
check**: it also reports success when path filtering determined that no
database-sensitive file changed, so it can be marked required without blocking
documentation-only pull requests.
