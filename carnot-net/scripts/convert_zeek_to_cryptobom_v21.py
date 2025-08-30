#!/usr/bin/env python3
import sys, json, csv, argparse, os

def detect_format(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        head = f.read(1024)
    if head.lstrip().startswith("{") or head.lstrip().startswith("["):
        return "json"
    return "tsv"

def tsv_to_obs(path):
    obs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line or line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if len(parts) < 9:
                continue
            ts = parts[0]
            version = parts[6] if len(parts) > 6 else None
            cipher = parts[7] if len(parts) > 7 else None
            sni = parts[8] if len(parts) > 8 else None
            obj = {
                "source":"network.zeek",
                "time": ts,
                "sni": sni,
                "tls_version": version,
                "cipher": cipher,
                "confidence": 0.9
            }
            obs.append(obj)
    return obs

def json_to_obs(path):
    obs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            sni = row.get("server_name") or row.get("sni")
            version = row.get("version") or row.get("tls_version")
            cipher = row.get("cipher")
            ts = row.get("ts") or row.get("_write_ts") or row.get("time")
            obj = {
                "source":"network.zeek",
                "time": ts,
                "sni": sni,
                "tls_version": version,
                "cipher": cipher,
                "confidence": 0.9
            }
            obs.append(obj)
    return obs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssl", required=True, help="Path to Zeek ssl.log (TSV or JSONL)")
    ap.add_argument("--out", required=True, help="Output observations JSONL")
    args = ap.parse_args()

    fmt = detect_format(args.ssl)
    if fmt == "tsv":
        observations = tsv_to_obs(args.ssl)
    else:
        observations = json_to_obs(args.ssl)

    with open(args.out, "w", encoding="utf-8") as o:
        for obj in observations:
            o.write(json.dumps(obj) + "\n")
    print(f"Wrote {len(observations)} observations to {args.out}")

if __name__ == "__main__":
    main()
