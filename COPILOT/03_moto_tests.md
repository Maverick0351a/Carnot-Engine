# Task 03 — AWS inventory: moto tests & untagged defaults

**Goal:** Make AWS inventory reliable with tests and sane defaults.

## Prompt
Copilot, enhance `integrations/aws/aws_inventory.py` and add tests:
1. If an asset **lacks context tags**, set defaults:
   - `owner: "unknown"`, `data_class: "unclassified"`, `secrecy_lifetime_years: 10`, `exposure: "internal"`
2. Add `integrations/aws/tests/test_inventory_moto.py` using **moto** to mock:
   - `list_keys` + `describe_key` + `list_resource_tags`
   - `list_certificates` + `describe_certificate`
   - Cover pagination & throttling retry behavior.
3. Add `Makefile` targets and `pytest` config to run tests in CI.

## Commands
```
pip install -r integrations/aws/requirements-dev.txt
pytest -q integrations/aws/tests
```

## Acceptance
- Tests pass in CI and locally.
- Untagged assets appear with default context fields in the BOM.
