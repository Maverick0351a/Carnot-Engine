import json, os, tempfile, subprocess, sys
from integrations.runtime.ebpf_to_bom import to_bom

SAMPLE_JSONL = """{"source":"runtime.ebpf","sni":"a.example","groups_offered":["X25519"],"handshake_success":true,"pid":11,"tid":22,"time":"2025-08-30T12:00:00Z","confidence":0.8}
{"source":"runtime.ebpf","sni":"b.example","groups":"X25519:P-256","success":false,"pid":33,"tid":44,"time":"2025-08-30T12:00:01Z","confidence":0.8}
invalid json line
"""

def test_to_bom_basic():
    ev = [{
        "source":"runtime.ebpf","sni":"example.org",
        "groups":"X25519:P-256","success":True,"pid":1,"tid":2
    }]
    bom = to_bom(ev)
    assert bom["schema"] == "carnot.v2.1.cryptobom"
    assert bom["observations"][0]["sni"] == "example.org"
    assert bom["observations"][0]["groups_offered"] == ["X25519","P-256"]

def test_cli_invocation(tmp_path):
    jin = tmp_path/"runtime.jsonl"
    jout = tmp_path/"runtime.bom.json"
    jin.write_text(SAMPLE_JSONL, encoding="utf-8")
    # run the CLI
    cmd = [sys.executable, "-m", "integrations.runtime.ebpf_to_bom", "--in", str(jin), "--out", str(jout)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    data = json.loads(jout.read_text(encoding="utf-8"))
    assert data["summary"]["observations"] == 2
    sns = sorted(o["sni"] for o in data["observations"])
    assert sns == ["a.example","b.example"]
