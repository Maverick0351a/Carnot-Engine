#!/usr/bin/env python3
import json, sys
if len(sys.argv)<3: print("Usage: jfr_to_bom.py jfr_print.txt output.json"); sys.exit(1)
txt=open(sys.argv[1],encoding="utf-8",errors="ignore").read()
obs=[]; sni=None; cipher=None; version="1.3"
for line in txt.splitlines():
  if "Peer Host:" in line: sni=line.split("Peer Host:")[-1].strip()
  if "Cipher Suite:" in line: cipher=line.split("Cipher Suite:")[-1].strip()
  if "Protocol Version:" in line or "Protocol:" in line: version=line.split(":")[-1].strip()
  if sni and cipher:
    obs.append({"source":"runtime.jfr","sni":sni,"cipher":cipher,"tls_version":version,"confidence":0.8})
    sni=None; cipher=None
json.dump({"schema":"carnot.v2.1.cryptobom","run_id":"jfr-"+sys.argv[1],"summary":{"assets":0,"observations":len(obs)},"observations":obs},
          open(sys.argv[2],"w",encoding="utf-8"), indent=2)
