# Carnot Engine — WORKLOG

> Purpose: A simple running log of work completed by Copilot or contributors.
> Rule: **Append a dated entry** (UTC) for each task. Include commands executed, files touched, and commit hashes.

## Template
- **Date (UTC):** YYYY-MM-DD
- **Task:** short description
- **Changes:** bullet list of files / functions changed
- **Commands:** exact commands run
- **Result:** pass/fail, test summary, build/deploy URLs
- **Commit:** <hash>  (link to PR if applicable)

---

## Entries

- **Date (UTC):** 2025-08-30
	**Task:** eBPF event correlation & runtime JSONL emission (Task 01)
	**Changes:**
		- Added `carnot-agent/ebpf-core/openssl_handshake.bpf.c` implementing SNI/groups/handshake probes with tid field.
		- Updated `carnot-agent/loader-go/main.go` to add tid, correlation map keyed by (pid, tid, ssl_ptr), expiration, JSONL output via `-out`, drop stats.
	**Commands:** (build/run to be executed by operator; stress test pending)
	**Result:** Code added; build & stress test still required; loss stats logic implemented.
	**Commit:** <pending>

- **Date (UTC):** 2025-08-30
	**Task:** Runtime JSONL to CryptoBOM v2.1 converter enhancements (Task 02)
	**Changes:**
		- Enhanced `integrations/runtime/ebpf_to_bom.py` with validation, normalized fields, streaming read.
		- Added CLI invocation test in `integrations/runtime/tests/test_ebpf_to_bom.py` including fixture JSONL & invalid line handling.
	**Commands:** python -m pytest integrations/runtime/tests/test_ebpf_to_bom.py
	**Result:** Local static checks pass (execution pending in CI/local run).
	**Commit:** <pending>

- **Date (UTC):** 2025-08-30
	**Task:** AWS inventory defaults & moto tests (Task 03)
	**Changes:**
		- Updated `integrations/aws/aws_inventory.py` adding default context + throttling retry.
		- Added dev requirements `integrations/aws/requirements-dev.txt`.
		- Added tests `integrations/aws/tests/test_inventory_moto.py` with moto for KMS & ACM, pagination/throttling simulation.
		- Added `pytest.ini` and `Makefile` targets (deps, aws-test).
	**Commands:** make aws-test
	**Result:** Pending execution; expects tests to pass.
	**Commit:** <pending>

- **Date (UTC):** 2025-08-30
	**Task:** OPA policy gate workflow (Task 04)
	**Changes:**
		- Added `.github/workflows/policy-gate.yml` with warn/enforce modes, PR comments, artifact upload.
		- Expanded `docs/POLICY_GUIDE.md` with violation mappings and remediation steps.
	**Commands:** (runs automatically on PRs)
	**Result:** Workflow ready; enforcement contingent on PR mode input.
	**Commit:** <pending>

- **Date (UTC):** 2025-08-30
	**Task:** Cloud Run FastAPI attestation endpoint (Task 05)
	**Changes:**
		- Added `api/` (FastAPI app `main.py`, requirements, Dockerfile, README).
		- Added deployment helper `scripts/gcloud-run.sh`.
		- Integrates `carnot-attest` to produce attestation JSON + Markdown path.
	**Commands:** docker build -t carnot-attest-api -f api/Dockerfile .
	**Result:** Scaffold complete; runtime test pending.
	**Commit:** <pending>

- **Date (UTC):** 2025-08-30
	**Task:** Cloudflare Pages site scaffold (Task 06)
	**Changes:**
		- Added `carnot-site/` (index.html, style.css, README with deployment instructions).
		- Enhanced sample docs in `docs/samples/` with guidance.
	**Commands:** (Deploy via Cloudflare Pages UI)
	**Result:** Instructions ready; awaiting initial Pages deployment.
	**Commit:** <pending>
