# Task 05 — Cloud Run API: /attest endpoint (scale-to-zero)

**Goal:** Minimal API that accepts a CryptoBOM v2.1 and returns an attestation (JSON + MD).

## Prompt
Copilot, scaffold `/api` with **FastAPI**:
- `POST /attest` accepts JSON body (CryptoBOM v2.1), returns:
  - `application/json` (attestation JSON)
  - and saves Markdown to `/tmp/attestation.md` (return path in response)
- Use our `carnot-attest` package to generate both.
- Add `requirements.txt`, `Dockerfile`, and `README.md` with `gcloud run deploy` steps.
- Add a `scripts/gcloud-run.sh` helper (project, region, service name parameters).

## Commands
```
cd api
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -e ../carnot-attest
uvicorn main:app --port 8080 --reload

# Deploy (in Cloud Shell)
gcloud builds submit --tag gcr.io/$PROJECT/carnot-attest-api
gcloud run deploy carnot-attest-api --image gcr.io/$PROJECT/carnot-attest-api --region us-central1 --platform managed --allow-unauthenticated --min-instances 0
```

## Acceptance
- Local run serves /attest and returns valid attestation JSON.
- Deployment succeeds with min instances = 0.
