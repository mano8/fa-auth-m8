#!/usr/bin/env bash
set -Eeuo pipefail

# CI-only helper: replace every literal 'changethis' placeholder secret value
# in this example's bootstrapped *.env files with a freshly generated strong
# value, so an unattended `docker compose up` can pass the issuer's
# fail-closed secret-strength validation (auth_sdk_m8.core.config.
# CommonSettings / auth_user_service.core.config.Settings).
#
# Real deployments replace 'changethis' by hand — init.sh already prints that
# reminder. This script exists only so example-smoke.yaml can prove the
# compose stack boots without a human in the loop; it never touches values
# that aren't the literal placeholder (e.g. DB_USER=changethis_auth_user is a
# compound identifier, not a validated secret, and is left untouched).
#
# A placeholder is NOT the same thing as an independent secret. Several
# 'changethis' occurrences across an example's env files are two ends of one
# credential, and seeding them independently produces a stack that boots but
# cannot authenticate — e.g. `.env` AUTH_DB_PASSWORD provisions the Postgres
# role that `auth.env` DB_PASSWORD then logs in as. So values are generated
# per *logical secret* (see canonical_group below) and reused everywhere that
# secret appears, rather than per occurrence.

gen_secret() {
    # 32+ chars, upper+lower+digit+special, no whitespace — satisfies both
    # SECRET_KEY_REGEX and PASSWORD_REGEX (auth_sdk_m8.schemas.shared).
    # Deliberately free of quotes, '$', '#' and whitespace so the value is
    # safe unquoted in a dotenv, in the compose ${VAR} substitution, in the
    # redis ACL command line, and inside the PRIVATE_API_CONSUMERS JSON.
    local body
    body="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 36)"
    printf 'Xz9!%s' "$body"
}

# group -> generated value, shared across every file in this example.
declare -A SECRET_VALUE=()

canonical_group() {
    # Map a (file, key) pair onto the logical secret it carries. Two pairs
    # that map to the same group always receive the same generated value.
    local file="$1" key="$2"
    case "${file}:${key}" in
        # Per-service DB credentials: `.env` drives shared/db_init/init-db.sh,
        # which CREATEs the role; the service's own env file then authenticates
        # as that role. Same key name, different secret — hence the explicit map.
        .env:AUTH_DB_PASSWORD | auth.env:DB_PASSWORD)
            printf 'auth-db-password' ;;
        .env:API_DB_PASSWORD | api.env:DB_PASSWORD)
            printf 'api-db-password' ;;
        *)
            case "$key" in
                # Genuinely one secret wherever the name appears:
                #   REDIS_PASSWORD      engine requirepass/ACL + both clients
                #   ACCESS/REFRESH_*    HS256 shared signing key (issuer+consumer)
                #   PRIVATE_API_SECRET  consumer credential, also embedded in the
                #                       issuer's PRIVATE_API_CONSUMERS JSON map
                #   EVENT_SIGNING_KEY   HMAC over the auth event stream
                REDIS_PASSWORD | ACCESS_SECRET_KEY | REFRESH_SECRET_KEY | \
                PRIVATE_API_SECRET | EVENT_SIGNING_KEY)
                    printf 'shared:%s' "$key" ;;
                # Everything else is scoped to its own file: the engine
                # superuser DB_PASSWORD/DB_ROOT_PASSWORD, SESSION_SECRET,
                # TOKENS_ENCRYPTION_KEY, FIRST_SUPERUSER_PASSWORD,
                # VAULT_DEV_TOKEN, GF_SECURITY_ADMIN_PASSWORD.
                *) printf 'file:%s:%s' "$file" "$key" ;;
            esac ;;
    esac
}

# Resolve (file, key) to its secret, generating it on first use. The result is
# returned in $REPLY rather than on stdout on purpose: called as $(secret_for …)
# the memo table would be populated inside a command-substitution subshell and
# discarded, handing every occurrence a fresh value — which is exactly the
# mismatch this script exists to prevent.
secret_for() {
    local group
    group="$(canonical_group "$1" "$2")"
    if [ -z "${SECRET_VALUE[$group]+set}" ]; then
        SECRET_VALUE[$group]="$(gen_secret)"
    fi
    REPLY="${SECRET_VALUE[$group]}"
}

for f in .env auth.env api.env grafana.env; do
    [ -f "$f" ] || continue
    tmp="$(mktemp)"
    # SC2094: $f is only ever *read* here — the loop redirects its output to
    # $tmp, and $f is passed to secret_for as a plain group-name argument, not
    # reopened. The rewritten file replaces $f via mv once the loop has closed.
    # shellcheck disable=SC2094
    while IFS= read -r line || [ -n "$line" ]; do
        # Tolerate a CRLF template (a Windows checkout of the *.env.example
        # files); a trailing CR would otherwise end up inside the secret.
        line="${line%$'\r'}"
        case "$line" in
            \#*)
                ;;
            # KEY=changethis, optionally followed by a trailing comment —
            # vault_dev_m8's .env annotates two of its secrets that way, and
            # an end-anchored match would silently skip them.
            *=changethis | *=changethis[[:space:]]*)
                key="${line%%=*}"
                rest="${line#*=changethis}"
                secret_for "$f" "$key"
                line="${key}=${REPLY}${rest}"
                ;;
            *'"secret":"changethis"'*)
                # The issuer's PRIVATE_API_CONSUMERS map. Its `secret` is the
                # far end of the consumer's PRIVATE_API_SECRET, so it resolves
                # to that same group rather than to a fresh value.
                secret_for "$f" PRIVATE_API_SECRET
                line="${line//\"secret\":\"changethis\"/\"secret\":\"${REPLY}\"}"
                ;;
        esac
        printf '%s\n' "$line"
    done < "$f" > "$tmp"
    mv "$tmp" "$f"
    chmod 600 "$f"
    echo "==> seeded CI-only secrets in $f"
done
