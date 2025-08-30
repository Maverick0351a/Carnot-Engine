# Task 10 — Enforce WORKLOG updates in PRs

**Goal:** Ensure every PR includes a WORKLOG entry.

## Prompt
Copilot, create `.github/workflows/worklog-check.yml` that:
- Fails PR if `WORKLOG.md` was not modified in the commit range.
- Posts a comment explaining the rule and linking to the template.
- Provide a bypass label `no-worklog-ok` for maintainers.

## Acceptance
- Workflow blocks PRs without WORKLOG changes unless label is set.
