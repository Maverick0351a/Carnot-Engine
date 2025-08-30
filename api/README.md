# Carnot Attestation API

FastAPI service exposing `/attest` to convert a CryptoBOM v2.1 into an attestation (JSON + Markdown).

## Local Development
```bash
cd api
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -e ../carnot-attest
uvicorn main:app --reload --port 8080
```
Test:
```bash
curl -X POST localhost:8080/attest -H 'Content-Type: application/json' -d '{"schema":"carnot.v2.1.cryptobom","summary":{"components":0,"observations":0},"observations":[]}'
```

## Docker Build
```bash
docker build -t carnot-attest-api -f api/Dockerfile .
docker run -p 8080:8080 carnot-attest-api
```

## Cloud Run Deploy
```bash
PROJECT=my-gcp-project
REGION=us-central1
SERVICE=carnot-attest-api
gcloud builds submit --tag gcr.io/$PROJECT/$SERVICE
gcloud run deploy $SERVICE --image gcr.io/$PROJECT/$SERVICE --region $REGION --platform managed --allow-unauthenticated --min-instances 0
```

## Response Shape
```json
{
  "attestation": {"attestation_schema": "carnot.v1.attestation", ...},
  "markdown_path": "/tmp/attestation.md"
}
```
