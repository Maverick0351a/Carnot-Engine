# Carnot Engine — Crypto Agility & Runtime Attestation Toolkit

**Discover → Plan → Automate → Verify** your cryptographic posture with a unified **CryptoBOM v2.1**.

## What’s inside
- `carnot-cli/` — static scanner → CryptoBOM v2.1
- `carnot-merge/` — merge multiple observation sources
- `carnot-attest/` — sign BOM → attestation (JSON + MD)
- `carnot-agent/` — eBPF uprobes + Go loader (runtime handshake observations)
- `integrations/windows/SChannelETW/` — ETW Schannel → JSONL
- `integrations/java/jfr/` — JFR TLS/crypto profile (JDK 11+)
- `tools/ingest/` — ETW/JFR → observations converters
- `carnot-net/` — Zeek/tshark converters (TLS/QUIC)
- `carnot-lab/` — OQS/OpenSSL 3 hybrid TLS interop lab
- `docs/matrices/*` — observability, compatibility, ROI, mapping
- Infra: `.devcontainer/`, `.vscode/`, `.github/workflows/`

See `docs/VALIDATION_STEPS.md` for hands-on verification.

## Recent additions
- Go userspace eBPF loader (`carnot-agent/loader-go`) emitting correlated handshake JSONL.
- AWS inventory defaults + moto tests.
- Policy gate workflow with warn/enforce and remediation comments.
- FastAPI `/attest` Cloud Run scaffold.
- Cloudflare Pages static site scaffold (`carnot-site/`).

## Quick Start (CLI Demo)
```bash
pip install -e ./carnot-cli
carnot ./carnot-cli/examples/demo-python -o cryptobom.json
pip install -e ./carnot-attest
carnot-attest --project Demo --bom cryptobom.json --out attest-out
```

## License
Apache-2.0 (see `LICENSE`).

## Contributing
See `WORKLOG.md` for task history. PRs welcome.
