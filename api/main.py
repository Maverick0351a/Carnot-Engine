from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import tempfile, os, json
from typing import Any, Dict
from datetime import datetime
from carnot_attest import attest

app = FastAPI(title="Carnot Attestation API", version="0.1.0")

class CryptoBOM(BaseModel):
    schema: str
    run_id: str | None = None
    summary: dict
    observations: list[Any]

@app.post("/attest")
async def create_attestation(bom: CryptoBOM, project: str = "API Project"):
    if not bom.schema.startswith("carnot.v2.1.cryptobom"):
        raise HTTPException(status_code=400, detail="Unsupported schema")
    # Write BOM to temp file
    tmpdir = tempfile.mkdtemp(prefix="attest-")
    bom_path = os.path.join(tmpdir, "input.bom.json")
    with open(bom_path, "w", encoding="utf-8") as f:
        json.dump(bom.model_dump(), f)
    out_dir = tempfile.mkdtemp(prefix="attestation-")
    attest.run(project, bom_path, out_dir)
    # Move markdown to /tmp for spec requirement
    md_src = os.path.join(out_dir, "attestation.md")
    md_target = "/tmp/attestation.md"
    try:
        if os.path.exists(md_src):
            os.replace(md_src, md_target)
    except Exception:
        pass
    att_json_path = os.path.join(out_dir, "attestation.json")
    result = json.load(open(att_json_path, encoding="utf-8"))
    return {"attestation": result, "markdown_path": md_target}

@app.get("/healthz")
async def health():
    return {"status":"ok","time": datetime.utcnow().isoformat()+"Z"}
