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

gen_secret() {
    # 32+ chars, upper+lower+digit+special, no whitespace — satisfies both
    # SECRET_KEY_REGEX and PASSWORD_REGEX (auth_sdk_m8.schemas.shared).
    local body
    body="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 36)"
    printf 'Xz9!%s' "$body"
}

shopt -s nullglob
for f in .env auth.env api.env grafana.env; do
    [ -f "$f" ] || continue
    tmp="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            \#*)
                ;;
            *=changethis)
                line="${line%%=*}=$(gen_secret)"
                ;;
            *'"secret":"changethis"'*)
                line="${line//\"secret\":\"changethis\"/\"secret\":\"$(gen_secret)\"}"
                ;;
        esac
        printf '%s\n' "$line"
    done < "$f" > "$tmp"
    mv "$tmp" "$f"
    chmod 600 "$f"
    echo "==> seeded CI-only secrets in $f"
done
