# vault/policies/app-policy.hcl — Read-only policy for the app secrets path.
#
# Apply with:
#   vault policy write app-read /vault/policies/app-policy.hcl
#
# Then create a scoped app token:
#   APP_TOKEN=$(vault token create -policy=app-read -period=24h -format=json \
#     | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
#
# The app token has read access only. It cannot write, delete, or list other paths.
# Rotate periodically or use a periodic token with Vault Agent auto-renewal.

path "secret/data/app" {
  capabilities = ["read"]
}

path "secret/metadata/app" {
  capabilities = ["read", "list"]
}
