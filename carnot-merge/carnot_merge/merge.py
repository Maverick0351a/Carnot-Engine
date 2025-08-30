import json, sys, argparse, datetime
def read_any(path):
    if path.endswith('.jsonl'):
        out=[]; 
        with open(path, encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try: out.append(json.loads(line))
                except: pass
        return out
    else:
        data=json.load(open(path,encoding='utf-8'))
        return data.get('observations', []) if isinstance(data, dict) else []
def merge(paths):
    merged=[]
    for p in paths: merged += read_any(p)
    return {"schema":"carnot.v2.1.cryptobom","run_id":"merge-"+datetime.datetime.utcnow().isoformat()+"Z","summary":{"assets":0,"observations":len(merged)},"observations":merged}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out","-o",default="merged-cryptobom.json")
    a=ap.parse_args()
    out=merge(a.inputs)
    json.dump(out, open(a.out,"w",encoding="utf-8"), indent=2)
    print(f"Wrote {a.out} with {out['summary']['observations']} observations.")
