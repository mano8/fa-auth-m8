#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

STACK_DIR="${1:-.}"

if [[ ! -d "$STACK_DIR" ]]; then
    echo "ERROR: preflight target is not a directory: $STACK_DIR" >&2
    exit 1
fi

cd "$STACK_DIR"

errors=()
warnings=()
env_files=()
cors_entries=()
doc_flag_entries=()
risky_flag_entries=()
production=false
strict_production=false

declare -A ENV_VALUES=()
declare -A ENV_SOURCES=()
declare -A SECRET_VALUE_GROUPS=()
declare -A SECRET_VALUE_SOURCES=()
declare -A DOC_FLAG_SEEN=()

trim() {
    printf '%s' "$1" | sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

unquote() {
    local value="$1"
    if [[ ${#value} -ge 2 ]]; then
        if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
            printf '%s' "${value:1:${#value}-2}"
            return
        fi
        if [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
            printf '%s' "${value:1:${#value}-2}"
            return
        fi
    fi
    printf '%s' "$value"
}

is_true() {
    local value
    value="$(lower "$(trim "${1:-}")")"
    [[ "$value" == "1" || "$value" == "true" || "$value" == "yes" || "$value" == "on" ]]
}

is_false() {
    local value
    value="$(lower "$(trim "${1:-}")")"
    [[ "$value" == "0" || "$value" == "false" || "$value" == "no" || "$value" == "off" ]]
}

add_error() {
    errors+=("$1")
}

add_warning() {
    warnings+=("$1")
}

is_sensitive_key() {
    local key="$1"
    [[ "$key" =~ (PASSWORD|SECRET|TOKEN|KEY)$ || "$key" =~ (PASSWORD|SECRET|TOKEN|KEY)_ ]]
}

is_high_value_key() {
    local key="$1"
    case "$key" in
        ACCESS_SECRET_KEY | REFRESH_SECRET_KEY | PRIVATE_API_SECRET | SESSION_SECRET | \
            TOKENS_ENCRYPTION_KEY | EVENT_SIGNING_KEY | FIRST_SUPERUSER_PASSWORD | \
            DB_ROOT_PASSWORD | DB_PASSWORD | *_DB_PASSWORD | REDIS_PASSWORD | \
            VAULT_DEV_TOKEN | GF_SECURITY_ADMIN_PASSWORD)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

secret_group_for() {
    local file="$1"
    local key="$2"
    local base
    base="$(basename "$file")"

    case "$key" in
        DB_PASSWORD)
            case "$base" in
                auth.env) printf '%s' "AUTH_DB_PASSWORD" ;;
                api.env) printf '%s' "API_DB_PASSWORD" ;;
                .env) printf '%s' "DB_ADMIN_PASSWORD" ;;
                *) printf '%s' "${file}:${key}" ;;
            esac
            ;;
        GF_SECURITY_ADMIN_PASSWORD)
            printf '%s' "GRAFANA_ADMIN_PASSWORD"
            ;;
        *)
            printf '%s' "$key"
            ;;
    esac
}

looks_like_default_secret() {
    local value
    value="$(lower "$(unquote "$(trim "${1:-}")")")"

    case "$value" in
        "" | changethis | changethis_* | *_changethis* | password | admin | root | \
            foobar | vault | vault-token | dev-token | devroot | secret | \
            "<inject-via-cicd>")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

has_local_origin() {
    local value
    value="$(lower "$1")"
    [[ "$value" == *"localhost"* || "$value" == *"127.0.0.1"* || \
        "$value" == *"0.0.0.0"* || "$value" == *"[::1]"* || "$value" == *"::1"* ]]
}

while IFS= read -r found; do
    env_files+=("${found#./}")
done < <(
    find . -maxdepth 3 -type f \
        \( -name '.env' -o -name '*.env' -o -name 'config.monitoring' \) \
        ! -name '*.example' \
        ! -name '*.prod_example' \
        | sort
)

for file in "${env_files[@]}"; do
    line_no=0
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        line_no=$((line_no + 1))
        line="$(trim "$raw_line")"
        [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
        [[ "$line" != *"="* ]] && continue

        key="$(trim "${line%%=*}")"
        value="$(trim "${line#*=}")"
        value="$(unquote "$value")"
        source="${file}:${line_no}"
        value_lower="$(lower "$value")"

        [[ -z "$key" ]] && continue
        ENV_VALUES["$key"]="$value"
        ENV_SOURCES["$key"]="$source"

        case "$key" in
            BACKEND_CORS_ORIGINS | CORS_ALLOWED_ORIGINS)
                cors_entries+=("${key}"$'	'"${source}"$'	'"${value}")
                ;;
            SET_DOCS | SET_OPEN_API | SET_REDOC)
                doc_flag_entries+=("${key}"$'	'"${source}"$'	'"${value}")
                DOC_FLAG_SEEN["$key"]=true
                ;;
            EVENT_SIGNING_ENABLED | TOKEN_STRICT_VALIDATION | ACCESS_REVOCATION_FAILURE_MODE)
                risky_flag_entries+=("${key}"$'	'"${source}"$'	'"${value}")
                ;;
        esac

        if [[ "$key" == "ENVIRONMENT" && "$value_lower" == "production" ]]; then
            production=true
        fi
        if [[ "$key" == "STRICT_PRODUCTION_MODE" ]] && is_true "$value"; then
            strict_production=true
        fi

        if [[ "$value_lower" == *"changethis"* ]]; then
            add_error "$source: replace placeholder value for $key"
        fi

        if [[ "$key" == *"PASSWORD"* && -z "$value" ]]; then
            add_error "$source: password value for $key must not be empty"
        fi

        if is_sensitive_key "$key"; then
            if [[ "$value" == *"<"*">"* || "$value_lower" == *"replace"* || \
                "$value_lower" == *"todo"* || "$value_lower" == *"inject-via-cicd"* ]]; then
                add_error "$source: $key still contains placeholder text"
            fi
            if [[ "$value" == *" #"* || "$value" == *$'	#'* ]]; then
                add_error "$source: $key contains an inline comment copied into the value"
            fi
        fi

        if [[ "$key" == "VAULT_DEV_TOKEN" ]] && looks_like_default_secret "$value"; then
            add_error "$source: VAULT_DEV_TOKEN must be generated and must not use a default"
        fi

        if [[ "$key" == "GF_SECURITY_ADMIN_PASSWORD" ]] && looks_like_default_secret "$value"; then
            add_error "$source: Grafana admin password must be generated and must not use a default"
        fi

        if [[ "$file" == ".env" && ( "$key" == "DB_ROOT_PASSWORD" || "$key" == "DB_PASSWORD" ) ]] && \
            looks_like_default_secret "$value"; then
            add_error "$source: root/admin database password must be generated and must not use a default"
        fi

        if is_high_value_key "$key" && [[ -n "$value" ]]; then
            group="$(secret_group_for "$file" "$key")"
            previous_groups="${SECRET_VALUE_GROUPS[$value]:-}"
            previous_sources="${SECRET_VALUE_SOURCES[$value]:-}"
            if [[ -z "$previous_groups" ]]; then
                SECRET_VALUE_GROUPS["$value"]="$group"
                SECRET_VALUE_SOURCES["$value"]="${group} at ${source}"
            elif [[ " ${previous_groups} " != *" ${group} "* ]]; then
                add_error "$source: secret value for ${group} is reused by ${previous_sources}"
                SECRET_VALUE_GROUPS["$value"]="${previous_groups} ${group}"
                SECRET_VALUE_SOURCES["$value"]="${previous_sources}; ${group} at ${source}"
            fi
        fi
    done < "$file"
done

serve_docs_in_production=false
if is_true "${ENV_VALUES[SERVE_DOCS_IN_PRODUCTION]:-}"; then
    serve_docs_in_production=true
fi

if [[ "$production" == "true" || "$strict_production" == "true" ]]; then
    for entry in "${cors_entries[@]}"; do
        IFS=$'	' read -r key source value <<< "$entry"
        if has_local_origin "$value"; then
            add_error "$source: $key must not include localhost origins in production/strict mode"
        fi
    done
fi

if [[ "$production" == "true" && "$serve_docs_in_production" != "true" ]]; then
    for key in SET_DOCS SET_OPEN_API SET_REDOC; do
        if [[ "${DOC_FLAG_SEEN[$key]:-}" != "true" ]]; then
            add_error "$key: must be false when ENVIRONMENT=production unless SERVE_DOCS_IN_PRODUCTION=true"
        fi
    done
    for entry in "${doc_flag_entries[@]}"; do
        IFS=$'	' read -r key source value <<< "$entry"
        if ! is_false "$value"; then
            add_error "$source: $key must be false when ENVIRONMENT=production unless SERVE_DOCS_IN_PRODUCTION=true"
        fi
    done
fi

risky_message_for() {
    local key="$1"
    case "$key" in
        EVENT_SIGNING_ENABLED)
            printf '%s' "EVENT_SIGNING_ENABLED=false disables signed event verification"
            ;;
        TOKEN_STRICT_VALIDATION)
            printf '%s' "TOKEN_STRICT_VALIDATION=false disables issuer/audience enforcement"
            ;;
        ACCESS_REVOCATION_FAILURE_MODE)
            printf '%s' "ACCESS_REVOCATION_FAILURE_MODE=fail_open allows access when revocation checks are unavailable"
            ;;
    esac
}

risky_bad_value_for() {
    local key="$1"
    case "$key" in
        EVENT_SIGNING_ENABLED | TOKEN_STRICT_VALIDATION)
            printf '%s' "false"
            ;;
        ACCESS_REVOCATION_FAILURE_MODE)
            printf '%s' "fail_open"
            ;;
    esac
}

for entry in "${risky_flag_entries[@]}"; do
    IFS=$'	' read -r key source value <<< "$entry"
    bad_value="$(risky_bad_value_for "$key")"
    if [[ "$(lower "$value")" == "$bad_value" ]]; then
        message="$(risky_message_for "$key")"
        if [[ "$strict_production" == "true" ]]; then
            add_error "$source: $message (blocked by STRICT_PRODUCTION_MODE=true)"
        else
            add_warning "$source: $message"
        fi
    fi
done

if [[ "$production" == "true" && "${ENV_VALUES[API_BIND_IP]:-}" == "0.0.0.0" ]]; then
    if ! is_true "${ENV_VALUES[ALLOW_PUBLIC_API_BIND]:-}" && \
        ! is_true "${ENV_VALUES[M8_ALLOW_PUBLIC_API_BIND]:-}"; then
        add_error "${ENV_SOURCES[API_BIND_IP]}: API_BIND_IP=0.0.0.0 is blocked in production; set ALLOW_PUBLIC_API_BIND=true only as a deliberate break-glass"
    fi
fi

stack_name="$(basename "$(pwd)")"
check_latest_images=false
if [[ "$production" == "true" || "$strict_production" == "true" || "$stack_name" == *"hardened"* || \
    "$stack_name" == *"production"* || "$stack_name" == *"prod"* ]]; then
    check_latest_images=true
fi

if [[ "$check_latest_images" == "true" ]]; then
    while IFS= read -r compose_file; do
        line_no=0
        while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            line_no=$((line_no + 1))
            line="$(trim "$raw_line")"
            [[ "$line" == image:*":latest"* ]] || continue
            add_error "${compose_file#./}:${line_no}: image tags must be pinned in hardened/production stacks, not :latest"
        done < "$compose_file"
    done < <(find . -maxdepth 2 -type f \( -name 'docker-compose.yml' -o -name 'docker-compose.*.yml' \) | sort)
fi

if [[ "${ENV_VALUES[VAULT_DEV_TOKEN]+set}" == "set" && "$production" == "true" ]]; then
    add_error "${ENV_SOURCES[VAULT_DEV_TOKEN]}: VAULT_DEV_TOKEN is for dev-mode Vault and must not be present in production"
fi

if [[ "$production" == "true" ]]; then
    while IFS= read -r compose_file; do
        line_no=0
        in_vault_service=false
        while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            line_no=$((line_no + 1))
            trimmed="$(trim "$raw_line")"
            # Detect a service named "vault" (service key at 2-space indent)
            if [[ "$raw_line" =~ ^[[:space:]]{2}vault[[:space:]]*: ]]; then
                in_vault_service=true
            elif [[ "$raw_line" =~ ^[[:space:]]{2}[a-zA-Z] && ! "$raw_line" =~ ^[[:space:]]{2}vault[[:space:]]*: ]]; then
                in_vault_service=false
            fi
            # Within the vault service, flag the -dev flag
            if [[ "$in_vault_service" == "true" ]] && \
               [[ "$trimmed" == *" -dev"* || "$trimmed" == "- -dev" || "$trimmed" == "\"-dev\"" || "$trimmed" == "'-dev'" ]]; then
                add_error "${compose_file#./}:${line_no}: Vault is configured in dev mode (ephemeral, root token); dev-mode Vault must not be used in production"
            fi
        done < "$compose_file"
    done < <(find . -maxdepth 2 -type f \( -name 'docker-compose.yml' -o -name 'docker-compose.*.yml' \) | sort)
fi

if [[ ${#warnings[@]} -gt 0 ]]; then
    echo "!! M8 security preflight warnings"
    for warning in "${warnings[@]}"; do
        echo "   - $warning"
    done
fi

if [[ ${#errors[@]} -gt 0 ]]; then
    echo "!! M8 security preflight failed"
    for error in "${errors[@]}"; do
        echo "   - $error"
    done
    exit 1
fi

echo "==> M8 security preflight passed"
