# vault/config/vault.hcl — Production Vault server configuration.
#
# Key differences from dev mode:
#   - Raft integrated storage (built-in HA, no external deps; swap to "file"
#     for single-node if preferred).
#   - TLS enabled on the listener (set real cert/key paths before use).
#   - No auto-unseal (configure cloud KMS or Vault auto-unseal for automation).
#   - ui = true is safe for internal-network Vault; disable if not needed.

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-node-1"
  # For multi-node HA, add retry_join blocks pointing at peer addresses.
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = false
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"
  # Optional: restrict client TLS versions
  # tls_min_version = "tls13"
}

# Advertised address (used in HA mode and by clients to reach this node).
# Set to the hostname or IP that other services use to reach Vault.
# api_addr = "https://vault.internal:8200"

ui = true
