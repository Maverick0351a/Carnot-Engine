# Placeholder: convert Zeek ssl.log TSV to JSONL minimal fields
import sys, json, csv
inp, outp = sys.argv[1], sys.argv[2]
with open(inp,encoding="utf-8") as f, open(outp,"w",encoding="utf-8") as o:
  r=csv.reader(f, delimiter="\t")
  for row in r:
    if not row or row[0].startswith("#"): continue
    # naive guess of columns
    ts=row[0]; server_name=row[8] if len(row)>8 else None; version=row[6] if len(row)>6 else None; cipher=row[7] if len(row)>7 else None
    o.write(json.dumps({"source":"network.zeek","time":ts,"sni":server_name,"tls_version":version,"cipher":cipher,"confidence":0.9})+"\n")
