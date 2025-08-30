import argparse, json, sys, datetime, os

def to_bom(events):
    obs = []
    for e in events:
        groups = e.get("groups") or e.get("groups_offered") or ""
        if isinstance(groups, str):
            groups_list = [g.strip() for g in groups.split(":") if g.strip()]
        else:
            groups_list = groups
        # normalize boolean field name
        hs = e.get("handshake_success")
        if hs is None:
            hs = e.get("success")
        # ensure time value present & RFC3339-ish
        t = e.get("time")
        if not t:
            t = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
        obs.append({
            "source": "runtime.ebpf",
            "asset_id": None,
            "owner": None,
            "data_class": None,
            "secrecy_lifetime_years": None,
            "exposure": None,
            "sni": e.get("sni"),
            "groups_offered": groups_list,
            "tls_version": e.get("tls_version"),
            "handshake_success": hs,
            "pid": e.get("pid"),
            "tid": e.get("tid"),
            "time": t,
            "confidence": 0.8
        })
    return {
        "schema": "carnot.v2.1.cryptobom",
        "run_id": "runtime-ebpf",
        "summary": {"components": 0, "observations": len(obs)},
        "observations": obs
    }

def validate_bom(bom: dict) -> None:
    """Basic shape validation; raises ValueError if invalid."""
    required_root = ["schema", "run_id", "summary", "observations"]
    for k in required_root:
        if k not in bom:
            raise ValueError(f"missing root key: {k}")
    if bom["schema"] != "carnot.v2.1.cryptobom":
        raise ValueError("unexpected schema")
    summ = bom.get("summary", {})
    if "observations" not in summ or "components" not in summ:
        raise ValueError("summary missing expected keys")
    if not isinstance(bom["observations"], list):
        raise ValueError("observations not a list")
    for i, o in enumerate(bom["observations"]):
        for field in ["source", "sni", "groups_offered", "handshake_success", "pid", "tid", "time", "confidence"]:
            if field not in o:
                raise ValueError(f"observation {i} missing {field}")
        if o["source"] != "runtime.ebpf":
            raise ValueError("invalid source")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="runtime JSONL from loader")
    ap.add_argument("--out", dest="out", required=True, help="output BOM json path")
    args = ap.parse_args()

    events = []
    # stream read lines; skip oversized lines quietly
    with open(args.inp, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                events.append(obj)
            except json.JSONDecodeError:
                print(f"warn: skipping invalid json line", file=sys.stderr)
                continue
    bom = to_bom(events)
    try:
        validate_bom(bom)
    except Exception as ex:
        print(f"Validation failed: {ex}", file=sys.stderr)
        sys.exit(1)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)
    print(f"Wrote {args.out} with {len(bom['observations'])} observations.")

if __name__ == "__main__":
    main()
