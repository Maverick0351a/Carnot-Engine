# Sustainable Deployment
- Site: Cloudflare Pages (Free). 
- API: Cloud Run (scale-to-zero; set max instances + budget alerts).
- Storage: GCS buckets for BOMs/attestations.
- Collectors: run on customer infra; exchange JSONL via pre-signed URLs.
