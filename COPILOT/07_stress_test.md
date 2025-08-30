# Task 07 — Stress test & overhead metrics (Golden Dataset)

**Goal:** Produce credible overhead numbers and artifacts.

## Prompt
Copilot, create `scripts/stress_test.sh` that:
- Installs `hey` if missing
- Runs 3 profiles (low/med/high) against a TLS endpoint (param)
- Captures `runtime.jsonl`, CPU usage (`mpstat`), and latency stats
- Computes drop rate vs successful handshakes observed

Also add `docs/METRICS_TEMPLATE.md` and write a runbook in `docs/GOLDEN_DATASET.md` referencing this script.

## Acceptance
- Script runs on Ubuntu with root privileges and outputs `metrics.json` + `runtime.jsonl`.
