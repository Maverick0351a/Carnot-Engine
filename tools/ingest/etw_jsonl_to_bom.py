#!/usr/bin/env python3
import json, sys
if len(sys.argv)<3: print("Usage: etw_jsonl_to_bom.py input.jsonl output.json"); sys.exit(1)
inp, outp = sys.argv[1], sys.argv[2]
obs=[]
for line in open(inp,encoding="utf-8"):
  line=line.strip()
  if not line: continue
  try: ev=json.loads(line)
  except: continue
  obs.append({"source":"runtime.etw","source_type":ev.get("source_type"),"pid":ev.get("pid"),
              "sni":ev.get("target_host"),"tls_version":ev.get("protocol"),"cipher":ev.get("ciphersuite"),
              "time":ev.get("timestamp"),"confidence":0.9})
json.dump({"schema":"carnot.v2.1.cryptobom","run_id":"etw-"+inp,"summary":{"assets":0,"observations":len(obs)},"observations":obs},
          open(outp,"w",encoding="utf-8"), indent=2)
