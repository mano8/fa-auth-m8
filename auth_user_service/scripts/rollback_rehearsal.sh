#!/usr/bin/env bash
# Non-rollback rehearsal (40-migration-release.md §4.5, MIG-CUTOVER-01).
#
# "Issuer rollback below 2.0 after Enforce is unsupported — forward-fix only"
# is a decided, tested claim, not just documented. This script proves it:
# it migrates a disposable database to Enforce head using the CURRENT (2.0)
# code, then starts the PREVIOUS issuer image against that same database and
# asserts it fails startup cleanly — a clear, actionable error, never a crash
# loop from an old write path attempting inconsistent updates.
#
# Requires Docker. Run from the repository root:
#
#   ./auth_user_service/scripts/rollback_rehearsal.sh [<previous-git-ref>] [<example>]
#
# <previous-git-ref> defaults to the latest reachable tag (git describe).
# <example> selects which maintained example's migration chain to certify
# (postgres_m8 | metrics_m8 | quickstart_m8 | rs256_m8); defaults to
# postgres_m8. Every resource this script creates is prefixed
# "fa-auth-rehearsal-" and is removed on exit, success or failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PREVIOUS_REF="${1:-$(git describe --tags --abbrev=0)}"
EXAMPLE="${2:-postgres_m8}"
NET="fa-auth-rehearsal-net"
DB="fa-auth-rehearsal-db"
NEW_APP="fa-auth-rehearsal-new"
OLD_APP="fa-auth-rehearsal-old"
NEW_IMAGE="fa-auth-rehearsal-new-image"
OLD_IMAGE="fa-auth-rehearsal-old-image"
WORKTREE="$(mktemp -d)/previous-issuer"
DB_PASSWORD='Rehearsal173!'

cleanup() {
  docker rm -f "${OLD_APP}" "${NEW_APP}" "${DB}" >/dev/null 2>&1 || true
  docker network rm "${NET}" >/dev/null 2>&1 || true
  docker rmi "${OLD_IMAGE}" "${NEW_IMAGE}" >/dev/null 2>&1 || true
  git worktree remove "${WORKTREE}" --force >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== Rehearsing rollback from ${PREVIOUS_REF} against the ${EXAMPLE} migration chain =="

docker network create "${NET}" >/dev/null

docker run -d --name "${DB}" --network "${NET}" \
  -e POSTGRES_PASSWORD="${DB_PASSWORD}" \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=auth_user \
  postgres:18.4-alpine >/dev/null

for _ in $(seq 1 30); do
  docker exec "${DB}" pg_isready -U auth_user 2>/dev/null | grep -q accepting && break
  sleep 2
done

cat > "${WORKTREE}.env" <<EOF
DOMAIN=localhost
ENVIRONMENT=local
PROJECT_NAME=fa-auth-m8
STACK_NAME=fa-auth-m8
API_PREFIX=/user
BACKEND_HOST=http://localhost:8000
FRONTEND_HOST=http://localhost:5173
BACKEND_CORS_ORIGINS=http://localhost:8000,http://localhost:5173
SELECTED_DB=Postgres
DB_HOST=${DB}
DB_PORT=5432
DB_DATABASE=auth_db
DB_USER=auth_user
DB_PASSWORD=${DB_PASSWORD}
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USER=appuser
REDIS_PASSWORD=TestRedis!Pass1secure
ACCESS_SECRET_KEY=TestAccess!Key4UnitTests_onlyXYZ0987
REFRESH_SECRET_KEY=TestRefresh!Key4UnitTests_onlyABC1234
ACCESS_TOKEN_ALGORITHM=HS256
REFRESH_TOKEN_ALGORITHM=HS256
TOKEN_STRICT_VALIDATION=false
EVENT_SIGNING_KEY=TestEvent!Signing4UnitTests_only5678
FIRST_SUPERUSER=admin@example.com
FIRST_SUPERUSER_PASSWORD=TestSuper!Pass1secure
PRIVATE_API_SECRET=TestPrivate!ApiSecret1secureXYZ098
SESSION_SECRET=TestSession!Secret1secureKeyABC123
TOKENS_ENCRYPTION_KEY=TestTokens!EncKey1secureKeyABC1234
GOOGLE_CLIENT_ID=test-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=TestGoogle!Secret1secureKeyXYZ098
EOF
# These exact values (mirrored from tests/conftest.py's hermetic unit-test
# env) are proven to satisfy every Settings field validator on both the
# current and the previous issuer version; REDIS_HOST/PORT are unreachable
# by design — this rehearsal only needs the DB connection, and using a real
# Redis dependency would make the rehearsal fail on an unrelated grey area.

echo "-- Building current (2.0) issuer image and migrating to Enforce head --"
docker build -q -t "${NEW_IMAGE}" -f auth_user_service/Dockerfile . >/dev/null
docker run -d --name "${NEW_APP}" --network "${NET}" --entrypoint sleep "${NEW_IMAGE}" infinity >/dev/null
docker cp "examples/docker_compose/${EXAMPLE}/shared_migrations" "${NEW_APP}:/opt/shared_migrations"
docker cp "${WORKTREE}.env" "${NEW_APP}:/opt/auth_user_service/.env"
docker exec -w /opt "${NEW_APP}" alembic -c auth_user_service/alembic.ini upgrade head

echo "-- Building previous issuer image (${PREVIOUS_REF}) --"
git worktree add "${WORKTREE}" "${PREVIOUS_REF}" >/dev/null
docker build -q -t "${OLD_IMAGE}" -f "${WORKTREE}/auth_user_service/Dockerfile" "${WORKTREE}" >/dev/null

echo "-- Starting the previous issuer against the Enforce-migrated database --"
docker create --name "${OLD_APP}" --network "${NET}" "${OLD_IMAGE}" >/dev/null
docker cp "${WORKTREE}.env" "${OLD_APP}:/opt/auth_user_service/.env"
docker cp "${WORKTREE}/examples/docker_compose/${EXAMPLE}/shared_migrations" "${OLD_APP}:/opt/shared_migrations"
docker start "${OLD_APP}" >/dev/null

# Give it a bounded window to reach a terminal state; a healthy/running
# container after this window means it did NOT fail closed — that is the
# rehearsal failing, not passing.
for _ in $(seq 1 20); do
  STATUS="$(docker inspect -f '{{.State.Status}}' "${OLD_APP}")"
  [ "${STATUS}" = "exited" ] && break
  sleep 1
done

STATUS="$(docker inspect -f '{{.State.Status}}' "${OLD_APP}")"
EXIT_CODE="$(docker inspect -f '{{.State.ExitCode}}' "${OLD_APP}")"
LOGS="$(docker logs "${OLD_APP}" 2>&1)"

echo "== Previous issuer final state: ${STATUS} (exit ${EXIT_CODE}) =="

if [ "${STATUS}" != "exited" ] || [ "${EXIT_CODE}" = "0" ]; then
  echo "REHEARSAL FAILED: the previous issuer did not fail closed against the Enforce-migrated schema."
  echo "${LOGS}"
  exit 1
fi

# Precise, not a loose keyword match: startup banner text like "Migrations
# already exist, skipping generation." also contains "migration" and would
# otherwise make an unrelated failure (bad secret, unreachable DB, ...) look
# like a passed rehearsal.
if ! echo "${LOGS}" | grep -qi "Can't locate revision\|alembic.util.messaging\|CommandError"; then
  echo "REHEARSAL FAILED: the previous issuer exited non-zero, but not with the expected"
  echo "Alembic unknown-revision error — this is not evidence of the rollback claim:"
  echo "${LOGS}"
  exit 1
fi

echo "REHEARSAL PASSED: the previous issuer failed startup cleanly. Last lines:"
echo "${LOGS}" | tail -5
