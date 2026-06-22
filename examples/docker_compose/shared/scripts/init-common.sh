#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Invoked by each example's thin init.sh after that script cd's into the example directory.
# BASH_SOURCE[0] resolves to this file; pwd is the caller's example directory.

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ROTATE_KEYS=false
ROTATE_CERTS=false
RESET_DB=false
RESET_YES=false

for arg in "$@"; do
    case "$arg" in
        --rotate-keys)  ROTATE_KEYS=true ;;
        --rotate-certs) ROTATE_CERTS=true ;;
        --rotate-all)   ROTATE_KEYS=true; ROTATE_CERTS=true ;;
        --reset-db)     RESET_DB=true ;;
        --yes)          RESET_YES=true ;;
        *)
            echo "Usage: init.sh [--rotate-keys] [--rotate-certs] [--rotate-all]"
            echo "               [--reset-db [--yes]]"
            exit 1 ;;
    esac
done

echo "==> M8 init: $(basename "$(pwd)")"

# --- Deployment security preflight (advisory — never blocks compose up) ---
# Shells out to the security-tests-m8 Python scanner.  The scanner's non-zero
# exit is captured and reported; init always proceeds regardless.
_preflight_rc=0
if command -v security-tests-m8 &>/dev/null; then
    security-tests-m8 preflight --deployment-root "$(pwd)" || _preflight_rc=$?
    if [[ $_preflight_rc -ne 0 ]]; then
        echo ""
        echo "NOTE: preflight found issues (see above) — fix all ERROR findings before production deployment."
        echo "      init will proceed regardless."
        echo ""
    fi
else
    echo "NOTE: security-tests-m8 not installed — skipping deployment preflight."
    echo "      Install: pip install security-tests-m8"
fi

# --- Bootstrap missing env files from .example counterparts ---
# Match every *.env.example in the example dir so each stack gets the env files
# it actually ships.  dotglob picks up the leading-dot ".env.example"; nullglob
# keeps the loop from running on a literal pattern when none exist.
_copied=()
shopt -s nullglob dotglob
for tmpl in *.env.example; do
    target="${tmpl%.example}"
    if [[ ! -f "$target" ]]; then
        cp "$tmpl" "$target"
        _copied+=("$target")
    fi
done
shopt -u nullglob dotglob
if [[ ${#_copied[@]} -gt 0 ]]; then
    echo ""
    echo "NOTE: copied example env files — replace every 'changethis' before 'docker compose up':"
    for f in "${_copied[@]}"; do echo "        $f"; done
    echo ""
fi

# --- Enforce chmod 600 on all runtime env files and private keys ---
_perm_enforced=()
while IFS= read -r _sf; do
    _mode="$(stat -c '%a' "$_sf" 2>/dev/null || echo "???")"
    if [[ "$_mode" != "600" ]]; then
        chmod 600 "$_sf"
        _perm_enforced+=("$_sf (was ${_mode})")
    fi
done < <(
    find . -maxdepth 1 -type f -name '*.env' ! -name '*.example' ! -name '*.prod_example' | sort
    find . -maxdepth 2 -type f \( -path './keys/private.*' \) | sort
)
if [[ ${#_perm_enforced[@]} -gt 0 ]]; then
    echo ""
    echo "NOTE: enforced chmod 600 on secret files (fixed permissive modes):"
    for _f in "${_perm_enforced[@]}"; do echo "        $_f"; done
    echo ""
fi

# --- DB reset (destructive, confirmation-gated) ---
if [[ "$RESET_DB" == "true" ]]; then
    echo ""
    echo "WARNING: --reset-db will stop all containers and permanently delete ./db_data/"
    echo "         init-db.sh will re-run automatically on next: docker compose up -d"
    if [[ "$RESET_YES" != "true" ]]; then
        # Fail fast in non-interactive environments to prevent accidental data loss in CI.
        if [[ ! -t 0 ]]; then
            echo "ERROR: --reset-db requires --yes when stdin is not a terminal"
            exit 1
        fi
        read -rp "         Are you sure? [y/N] " confirm
        [[ "$confirm" == "y" || "$confirm" == "Y" ]] || { echo "Aborted."; exit 0; }
    fi
    docker compose down
    rm -rf db_data/
    echo "==> db_data/ removed — DB will reinitialize on next: docker compose up -d"
fi

# --- Legacy volume warnings ---
for old_vol in mysql_db postgres_data; do
    if [[ -d "./${old_vol}" ]]; then
        echo "WARNING: legacy volume './${old_vol}/' found — delete it before 'docker compose up'"
    fi
done
if [[ -d "./db_data" ]]; then
    echo "NOTE: db_data/ exists — init-db.sh will NOT re-run (reset with: bash init.sh --reset-db)"
fi

# --- Crypto lifecycle ---
run_init() {
    local script="$1" rotate="$2"
    if [[ "$rotate" == "true" ]]; then
        bash "${COMMON_DIR}/${script}" --rotate
    else
        bash "${COMMON_DIR}/${script}"
    fi
}

run_init "init-keys.sh"  "$ROTATE_KEYS"
run_init "init-certs.sh" "$ROTATE_CERTS"

echo "==> Done — DB init runs automatically on first: docker compose up -d"
