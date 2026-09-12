#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROTATE=false
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --rotate) ROTATE=true; shift ;;
        *) echo "Usage: $0 [--rotate]"; exit 1 ;;
    esac
done

AUTH_ENV="./auth.env"
KEYS_DIR="./keys"

# Write KEY=VALUE into auth.env, replacing an existing line (commented or not)
# or appending when the key is absent. Same temp-file approach as below: no
# sed -i, which differs between macOS and GNU.
set_env_var() {
    local key="$1" value="$2" tmp
    tmp=$(mktemp)
    if grep -qE "^#? *${key}=" "$AUTH_ENV"; then
        sed "s|^#\? *${key}=.*|${key}=${value}|" "$AUTH_ENV" > "$tmp"
    else
        cat "$AUTH_ENV" > "$tmp"
        printf '%s=%s\n' "$key" "$value" >> "$tmp"
    fi
    mv "$tmp" "$AUTH_ENV"
    echo "    set ${key}=${value} in ${AUTH_ENV}"
}

# KID: SHA256 of canonical DER bytes — stable across PEM formatting differences.
# Pure openssl pipeline — no Python dependency (avoids Windows Store stub issue).
# awk '{print $NF}' extracts the hex digest regardless of OpenSSL version prefix format.
# The service derives the same value (auth_user_service/core/key_ids.py) and
# refuses to boot if ACCESS_KEY_ID does not match it.
derive_kid() {
    openssl pkey -pubin -in "$1" -pubout -outform DER 2>/dev/null \
      | openssl dgst -sha256 2>/dev/null \
      | awk '{print $NF}' \
      | cut -c1-16
}

[[ -f "$AUTH_ENV" ]] || { echo "ERROR: ${AUTH_ENV} not found — run from example directory"; exit 1; }

# awk: single process, returns 0 on no-match — safe under pipefail unlike grep|cut|tr
ACCESS_ALGO="$(awk -F= '/^ACCESS_TOKEN_ALGORITHM=/{gsub(/["'"'"'[:space:]]/, "", $2); print $2}' "$AUTH_ENV")"
[[ -n "$ACCESS_ALGO" ]] || { echo "ERROR: ACCESS_TOKEN_ALGORITHM not found in ${AUTH_ENV}"; exit 1; }

if [[ "$ACCESS_ALGO" != RS* ]] && [[ "$ACCESS_ALGO" != ES* ]]; then
    echo "==> init-keys: ${ACCESS_ALGO} — no key files needed"; exit 0
fi

mkdir -p "$KEYS_DIR"
PRIV="${KEYS_DIR}/private.pem"
PUB="${KEYS_DIR}/public.pem"
PUB_OLD="${KEYS_DIR}/public_old.pem"

# SC2091: string comparison, not command execution
#
# Keys already exist and no rotation was requested — but "skipping" must not
# mean "not looking". Re-derive the kid from the mounted public key and
# compare it against the configured ACCESS_KEY_ID: an unbound or stale value
# here is exactly the J1 defect this script exists to prevent, and it must
# not survive a second `bash init.sh` silently. Absent -> write it. Mismatch
# -> re-bind and say so loudly. Match -> confirm and move on. This is a
# correction, not a rotation: the _OLD pair (if any) is left untouched.
if [[ -f "$PRIV" ]] && [[ "$ROTATE" != "true" ]]; then
    if [[ ! -f "$PUB" ]]; then
        echo "==> init-keys: keys exist, skipping (${PUB} missing — cannot verify binding, run --rotate)"
        exit 0
    fi
    existing_kid="$(derive_kid "$PUB")"
    if [[ -z "$existing_kid" ]]; then
        echo "==> init-keys: keys exist, skipping (${PUB} unreadable — cannot verify binding)"
        exit 0
    fi
    configured_kid="$(awk -F= '/^ACCESS_KEY_ID=/{gsub(/["'"'"'[:space:]]/, "", $2); print $2}' "$AUTH_ENV")"
    if [[ -z "$configured_kid" ]]; then
        echo "==> init-keys: keys exist, ACCESS_KEY_ID unset — binding to ${existing_kid}"
        set_env_var "ACCESS_KEY_ID" "$existing_kid"
    elif [[ "$configured_kid" == "$existing_kid" ]]; then
        echo "==> init-keys: keys exist, ACCESS_KEY_ID=${existing_kid} already bound"
    else
        echo "NOTE: ACCESS_KEY_ID=${configured_kid} does not match the mounted key (expected ${existing_kid}) — re-binding"
        set_env_var "ACCESS_KEY_ID" "$existing_kid"
    fi
    exit 0
fi

# Rotation overlap window: retain the outgoing PUBLIC key so JWKS keeps serving
# it while access tokens signed under it are still alive, and consumers need no
# restart. The outgoing PRIVATE key is deliberately not retained — it has no
# remaining job and must not stay mounted.
if [[ "$ROTATE" == "true" ]] && [[ -f "$PUB" ]]; then
    cp "$PUB" "$PUB_OLD"
    chmod 644 "$PUB_OLD"
    old_kid=$(derive_kid "$PUB_OLD")
    [[ -n "$old_kid" ]] || { echo "ERROR: failed to compute KID from ${PUB_OLD}" >&2; exit 1; }
    echo "==> Retaining previous public key for the JWKS overlap window"
    # Mirror whatever container path this stack mounts the key set at, rather
    # than assuming /opt/keys — the script is vendored into other stacks.
    pub_mount="$(awk -F= '/^ACCESS_PUBLIC_KEY_FILE=/{gsub(/["'"'"'[:space:]]/, "", $2); print $2}' "$AUTH_ENV")"
    [[ -n "$pub_mount" ]] || pub_mount="/opt/keys/public.pem"
    set_env_var "ACCESS_PUBLIC_KEY_OLD_FILE" "${pub_mount%/*}/public_old.pem"
    set_env_var "ACCESS_KEY_ID_OLD" "$old_kid"
    echo "    close the window once ACCESS_TOKEN_EXPIRE_MINUTES + the consumers'"
    echo "    JWKS_CACHE_TTL_SECONDS have passed: unset both vars above, redeploy,"
    echo "    and delete ${PUB_OLD}"
fi

echo "==> Generating keys for ${ACCESS_ALGO}"
# No 2>/dev/null — real failures (missing openssl, unsupported algo) must surface
case "$ACCESS_ALGO" in
    RS256|RS384)
        openssl genrsa -out "$PRIV" 2048
        openssl rsa -in "$PRIV" -pubout -out "$PUB" ;;
    RS512)
        openssl genrsa -out "$PRIV" 4096
        openssl rsa -in "$PRIV" -pubout -out "$PUB" ;;
    ES256)
        openssl ecparam -name prime256v1 -genkey -noout -out "$PRIV"
        openssl ec -in "$PRIV" -pubout -out "$PUB" ;;
    ES384)
        openssl ecparam -name secp384r1 -genkey -noout -out "$PRIV"
        openssl ec -in "$PRIV" -pubout -out "$PUB" ;;
    ES512)
        openssl ecparam -name secp521r1 -genkey -noout -out "$PRIV"
        openssl ec -in "$PRIV" -pubout -out "$PUB" ;;
    *) echo "ERROR: unsupported algorithm ${ACCESS_ALGO}"; exit 1 ;;
esac

chmod 600 "$PRIV" && chmod 644 "$PUB"

# Behavior-based capability guard: test DER export on the actual generated key.
# Catches broken openssl builds without relying on --help flag heuristics.
openssl pkey -pubin -in "$PUB" -pubout -outform DER >/dev/null 2>&1 || {
    echo "ERROR: OpenSSL cannot export DER from ${PUB} — pkey subcommand unsupported or broken build"
    exit 1
}

kid=$(derive_kid "$PUB")

[[ -n "$kid" ]] || { echo "ERROR: failed to compute KID from ${PUB}" >&2; exit 1; }

# The keypair and the kid that labels it are written in the same step — the one
# guarantee that keeps them bound. The service validates the binding at startup.
set_env_var "ACCESS_KEY_ID" "$kid"

echo "==> init-keys done: ${PRIV}, ${PUB}"
