# Carnot Site (Cloudflare Pages)

Static site served from this `carnot-site/` directory.

## Deploy to Cloudflare Pages
1. In Cloudflare Dashboard go to Pages > Create project.
2. Connect GitHub and select this repository.
3. Set Production branch (e.g. `main`).
4. Build settings:
   - Framework preset: `None`
   - Root directory: `carnot-site/`
   - Build command: (leave empty)
   - Build output directory: (leave empty — root will be served)
5. Save & Deploy. First deploy should publish the static HTML.
6. Add custom domain (optional) under Pages project settings.

## Public Samples
Links below surface repository samples directly (ensure they are committed):
- Attestation Markdown: `docs/samples/attestation.md`
- PCAP Proof Image: `docs/samples/pcap-proof.png`

To link them from the site, relative references are used in `index.html`. Replace placeholder content with real sanitized artifacts when ready.

## Updating Content
Commit changes to `carnot-site/` or `docs/samples/` — Cloudflare Pages auto‑builds.

## Notes
- No build step for now; can migrate to a static generator later.
- Keep artifacts small for fast cold loads.
