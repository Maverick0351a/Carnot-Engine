#!/usr/bin/env bash
set -euo pipefail
PROJECT=${1:?project id}
REGION=${2:-us-central1}
SERVICE=${3:-carnot-attest-api}
IMG=gcr.io/$PROJECT/$SERVICE

echo "Building $IMG"
gcloud builds submit --tag $IMG

echo "Deploying to Cloud Run: $SERVICE ($REGION)"
gcloud run deploy $SERVICE --image $IMG --region $REGION --platform managed --allow-unauthenticated --min-instances 0
