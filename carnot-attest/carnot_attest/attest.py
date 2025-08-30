import json, os, argparse, datetime, base64
from nacl.signing import SigningKey
from jinja2 import Template
TEMPLATE = """# Carnot Attestation
**Project:** {{ project }}  
**Generated:** {{ gen }}
**Input:** {{ inp }}
## Summary
- HNDL candidates: {{ hndl_candidates }}
- HNDL exposed: {{ hndl_exposed }} ({{ hndl_pct }}%)
- Observations: {{ total }}
- High: {{ high }} | Medium: {{ medium }} | Low: {{ low }}
---
Signature (ed25519, base64): {{ sig }}
PubKey (base64): {{ pk }}
"""
def classify(o):
    k=o.get("finding","")
    if k=="rsa_keygen":
        s=o.get("size") or 0
        if s and s<2048: return "high"
        if s and s<3072: return "medium"
        return "low"
    if k=="tls_context": return "medium"
    return "low"
def run(project, bom_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    bom=json.load(open(bom_path,encoding="utf-8"))
    obs=bom.get("observations",[])
    risk={"high":0,"medium":0,"low":0}
    for o in obs: risk[classify(o)] += 1
    sk=SigningKey.generate()
    payload={"attestation_schema":"carnot.v1.attestation","project":project,"generated_at":datetime.datetime.utcnow().isoformat()+"Z","input":os.path.basename(bom_path),"summary":{"total_observations":len(obs),"high":risk["high"],"medium":risk["medium"],"low":risk["low"]}}
    msg=json.dumps(payload,separators=(",",":")).encode()
    sig=sk.sign(msg).signature
    b64=lambda b: base64.b64encode(b).decode()
    payload["signature"]={"algorithm":"ed25519","value":b64(sig),"public_key_b64":b64(sk.verify_key.encode())}
    json.dump(payload, open(os.path.join(out_dir,"attestation.json"),"w",encoding="utf-8"), indent=2)
    md=Template(TEMPLATE).render(project=project, gen=payload["generated_at"], inp=payload["input"], total=len(obs), high=risk["high"], medium=risk["medium"], low=risk["low"], sig=b64(sig), pk=b64(sk.verify_key.encode()))
    open(os.path.join(out_dir,"attestation.md"),"w",encoding="utf-8").write(md)
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--bom", required=True)
    ap.add_argument("--out", default="./out")
    a=ap.parse_args()
    run(a.project, a.bom, a.out)
