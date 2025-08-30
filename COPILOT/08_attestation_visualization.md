# Task 08 — Visualize HNDL exposure in the attestation

**Goal:** Add a simple visualization (matplotlib) to make HNDL risk tangible.

## Prompt
Copilot, add `carnot-attest/addons/visualize_hndl.py` that:
- Reads `attestation.json`
- Creates a simple bar chart or small Sankey-like diagram showing:
  - total long-life observations vs. HNDL-exposed
- Saves `attestation_hndl.png` next to the JSON/MD

**Constraints:** Use **matplotlib** only (no seaborn), one chart per figure, default colors.

## Commands
```
python3 carnot-attest/addons/visualize_hndl.py --in carnot-attest/out/attestation.json --out carnot-attest/out/attestation_hndl.png
```

## Acceptance
- PNG renders and is referenced in `docs/samples/attestation.md`.
