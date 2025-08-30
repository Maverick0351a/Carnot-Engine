# Task 02 — Convert runtime JSONL → CryptoBOM v2.1

**Goal:** Convert the Go loader's `runtime.jsonl` into a CryptoBOM v2.1 JSON file (`runtime.bom.json`) for merging.

## Prompt
Copilot, create `integrations/runtime/ebpf_to_bom.py`:
- Read `runtime.jsonl` (line-delimited JSON).
- For each entry, emit a v2.1 observation with fields:
  - `source: "runtime.ebpf"`
  - `sni`, `groups_offered`, `tls_version` (if available), `handshake_success`
  - `pid`, `tid`, `time`
  - `confidence: 0.8`
- Write to `runtime.bom.json` with structure:
  ```json
  {"schema":"carnot.v2.1.cryptobom","run_id":"runtime-ebpf","summary":{"components":0,"observations":N},"observations":[...]}
  ```

Also add a unit test `integrations/runtime/tests/test_ebpf_to_bom.py` with a small fixture JSONL.

## Commands
```
python3 integrations/runtime/ebpf_to_bom.py --in runtime.jsonl --out runtime.bom.json
```

## Acceptance
- `runtime.bom.json` validates (basic shape) and merges cleanly via `carnot-merge`.
