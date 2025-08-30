# Task 04 — OPA gate (warn→enforce) with actionable messages

**Goal:** Improve developer experience and collect friction metrics.

## Prompt
Copilot, update `.github/workflows/policy-gate.yml` to:
- Run OPA on PRs against `merged.json` if present; else skip with notice.
- Post a PR comment summarizing violations with **action links** to docs.
- Respect a workflow input `mode` with values `warn` (default) or `enforce`.
- Emit a JSON artifact `opa_result.json` for later analytics.

Also add `docs/POLICY_GUIDE.md` mapping each violation to remediation steps.

## Acceptance
- On a PR with sample violations, the workflow posts a helpful comment and uploads `opa_result.json`.
