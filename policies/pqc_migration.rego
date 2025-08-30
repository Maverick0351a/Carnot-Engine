package carnot.pqc_migration
import time
deadline := time.parse_rfc3339_ns("2026-01-01T00:00:00Z")
required := {"X25519MLKEM768","P256MLKEM768"}

deny[msg] {
  input.resource_type == "tls_endpoint"
  input.exposure == "external"
  time.now_ns() > deadline
  not some g in input.offered_groups
  count(required & input.offered_groups) == 0
  msg := sprintf("External TLS endpoint must offer hybrid groups by deadline: %v", [required])
}

deny[msg] {
  input.resource_type == "configuration_change"
  input.algorithm == "RSA"
  input.key_size < 2048
  msg := "RSA key size below 2048"
}


# Developer-friendly messages and links
deny[msg] if {
    input.resource_type == "configuration_change"
    input.algorithm == "RSA"
    input.key_size < config.min_rsa_key_size
    msg := sprintf("VIOLATION: RSA key size %d < %d. Use Carnot.Sign(policy='PQC-Hybrid') — docs: https://carnotengine.com/docs/crypto-agility", [input.key_size, config.min_rsa_key_size])
}
