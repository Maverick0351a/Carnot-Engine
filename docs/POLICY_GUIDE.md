# Policy Guide (OPA) — Remediation Cheatsheet

This guide maps OPA `deny` messages to actionable remediation steps.

## Violations

### External TLS endpoint must offer hybrid groups by deadline
Message contains: `External TLS endpoint must offer hybrid groups by deadline`

Remediation:
1. Add at least one required hybrid PQC group (e.g. `X25519MLKEM768` or `P256MLKEM768`) to the TLS config.
2. Redeploy edge / load balancer.
3. Re-run scan to confirm violation cleared.

### RSA key size below 2048 / VIOLATION: RSA key size < min
Message variants:
- `RSA key size below 2048`
- `VIOLATION: RSA key size < ...`

Remediation:
1. Regenerate key with size >= 2048 (consider 3072 or migrate to hybrid scheme via `Carnot.Sign(policy="PQC-Hybrid")`).
2. Rotate certificates referencing the old key.
3. Update infra automation to enforce new minimum.

### TLS-HYBRID-001 (shorthand)
Enable hybrid groups (e.g., `X25519MLKEM768`). See `carnot-interop-lab/README.md`.

### SIG-PQC-002
Replace direct crypto calls with the agility SDK: `Carnot.Sign(policy="PQC-Hybrid")`.

### RSA-MIN-SIZE
Ensure RSA >= 2048 (prefer ECDSA or PQC signatures).

## Local Evaluation
```bash
opa eval -i merged.json -d policies "data.carnot.pqc_migration.deny"
```

## Analytics
Workflow artifact `opa_result.json` => `{ "violations": [..], "count": N }` for trend tracking.
