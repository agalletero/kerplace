# Persistent, TLS-enabled Vault acting as KerPlace's external KMS.
#
# Unlike dev mode, this keeps its Transit key on disk (file storage, in the
# `vault-data` volume) so it survives restarts — which is what makes a KerPlace
# bucket encrypted against it durable.
ui = true

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/vault.crt"
  tls_key_file  = "/vault/tls/vault.key"
}

# Reached only via the SSH reverse tunnel as https://localhost:8200.
api_addr = "https://127.0.0.1:8200"

# mlock keeps Vault's master key off swap; the container has CAP_IPC_LOCK.
disable_mlock = false
