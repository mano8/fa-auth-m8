# vault_prod_template

> **Reference template — not runnable as-is.**
> This directory provides annotated templates for connecting the fa-auth-m8 stack
> to a production-grade HashiCorp Vault instance. It intentionally omits secrets
> and the Vault server itself (Vault is long-lived infrastructure, not a compose
> service). See [`vault_dev_m8/`](../vault_dev_m8/) to run a local dev-mode Vault
> and learn the VaultProvider injection pattern first.

---

## What this template provides

| File | Purpose |
| --- | --- |
| `vault/config/vault.hcl` | Vault server config: Raft storage, TLS enabled, no dev mode |
| `vault/policies/app-policy.hcl` | Read-only policy scoped to the app secrets path |
| `docker-compose.app.yml.template` | App-compose snippet: connects auth service to external Vault via a Docker secret file (no `VAULT_DEV_TOKEN` in env) |

---

## How to use

### Step 1 — Run Vault as a separate stack

Vault is long-lived infrastructure; it must outlive any single app deployment.
Run it as a dedicated stack or use a managed service (HCP Vault, AWS Secrets Manager).

If running locally (persistence across restarts):

```sh
# 1. Start Vault in server mode (see vault/config/vault.hcl)
docker run -d --name vault \
  --cap-add IPC_LOCK \
  -v $(pwd)/vault/config:/vault/config:ro \
  -v vault_data:/vault/data \
  -p 127.0.0.1:8200:8200 \
  hashicorp/vault:1.17 server -config=/vault/config/vault.hcl

# 2. Initialize and save keys securely
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 vault vault operator init

# 3. Unseal (repeat with 3 of 5 keys)
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 vault vault operator unseal <key1>
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 vault vault operator unseal <key2>
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 vault vault operator unseal <key3>
```

### Step 2 — Write app secrets and create a scoped token

```sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<root-token-from-init>   # root token used ONCE for setup only

# Enable KV v2
vault secrets enable -path=secret kv-v2

# Write app secrets
vault kv put secret/app \
  DB_PASSWORD=<auth-db-password> \
  REDIS_PASSWORD=<redis-password>

# Create a read-only policy and a scoped app token
vault policy write app-read vault/policies/app-policy.hcl
APP_TOKEN=$(vault token create -policy=app-read -period=24h -ttl=24h -format=json \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

# Store the scoped token as a Docker secret file (never in a .env)
mkdir -p secrets
echo "$APP_TOKEN" > secrets/vault_token
chmod 600 secrets/vault_token
```

> The root token is used **once** during initial setup. The app receives only the
> scoped `APP_TOKEN` (read-only on `secret/data/app`). Rotate `APP_TOKEN` regularly
> via a periodic token or Vault Agent auto-renewal.

### Step 3 — Wire the app compose

Copy the snippet from `docker-compose.app.yml.template` into your stack's
`docker-compose.yml`. Key differences from `vault_dev_m8`:

- No `vault` or `vault_init` service in the app compose.
- `VAULT_DEV_TOKEN` is absent from every env file.
- The app token arrives via a Docker secret file at `/run/secrets/vault_token`
  (VaultProvider reads it automatically).
- `VAULT_ADDR` points at the external Vault host/port.

---

## Production checklist

- [ ] Vault runs in **server mode** (not `-dev`) with persistent Raft or file storage.
- [ ] Vault listener has **TLS enabled** (`tls_disable = false`, valid cert/key).
- [ ] The app uses a **scoped token** (`app-read` policy) — not the root token.
- [ ] `VAULT_DEV_TOKEN` is **absent** from all env files and compose `environment` blocks.
- [ ] The app token is delivered via a **Docker secret file** (`/run/secrets/vault_token`),
  not an environment variable.
- [ ] Token renewal is automated (periodic token TTL or Vault Agent sidecar).
- [ ] Vault is deployed **separately** from the app compose (independent lifecycle).
- [ ] Vault access is network-restricted to specific services.
- [ ] Unseal keys and root token are stored securely (HSM, cloud KMS, or split custody).
- [ ] `ENVIRONMENT=production` and `STRICT_PRODUCTION_MODE=true` are set in the app env.

---

> [Docker Compose examples](../README.md) · [Repository root](https://github.com/mano8/fa-auth-m8/tree/main)
