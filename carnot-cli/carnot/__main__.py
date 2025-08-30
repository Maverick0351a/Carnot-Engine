import argparse, json, sys, os
from .scan import run
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".", help="Project root to scan")
    ap.add_argument("--out","-o", default="cryptobom.json")
    ap.add_argument("--context", help="JSON file with asset_id/owner/data_class/secrecy_lifetime_years/exposure")
    a = ap.parse_args()
    ctx = {}
    if a.context and os.path.exists(a.context):
        ctx = json.load(open(a.context, encoding="utf-8"))
    bom = run(a.path, ctx)
    json.dump(bom, open(a.out,"w",encoding="utf-8"), indent=2)
    print(f"Wrote {a.out} with {bom['summary']['observations']} observations.")
if __name__ == "__main__": main()
