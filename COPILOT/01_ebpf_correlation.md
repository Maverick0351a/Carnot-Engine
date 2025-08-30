# Task 01 — eBPF Event Correlation & Stability (High Priority)

**Goal:** Correlate `EVT_SNI_SET`, `EVT_GROUPS_SET`, and `EVT_HANDSHAKE_RET` from the Go loader into **Handshake Observations** keyed by `(pid, tid, ssl_ptr)` within a 2s window. Emit JSONL suitable for CryptoBOM v2.1.

## Prompt
Copilot, implement robust event correlation in the runtime pipeline:
1. **Update BPF struct & loader** to include **TID** in every event.
   - File: `carnot-agent/ebpf-core/openssl_handshake.bpf.c`
   - Field: `__u32 tid;`
   - Set `tid = (__u32)bpf_get_current_pid_tgid();` on each event.
   - Update Go struct in `go-loader/main.go` accordingly.
2. In the Go loader, add a **time-limited map** `(pid, tid, ssl_ptr) -> partial state {sni, groups, t0}`.
   - On `tls.sni.set`: store/merge SNI.
   - On `tls.groups.set`: store/merge groups.
   - On `tls.handshake.ret`: finalize observation with `success`, write one JSON line.
   - Expire stale entries (>2s) periodically.
3. Write JSON lines to `runtime.jsonl` with fields:
   ```json
   {
     "source":"runtime.ebpf",
     "asset_id": null,
     "owner": null,
     "data_class": null,
     "secrecy_lifetime_years": null,
     "exposure": null,
     "sni":"...",
     "groups_offered":["X25519","P-256"],
     "handshake_success":true,
     "pid":1234,
     "tid":5678,
     "ssl_ptr":"0x...",
     "time":"2025-08-30T12:00:00Z",
     "confidence":0.8
   }
   ```
4. Add a CLI flag `-out runtime.jsonl` to the loader to write to file.
5. **Stress test** with `hey -n 5000 -c 50 https://example.org` and ensure event loss is minimal (<1%). Print drop statistics.

## Commands
```
cd carnot-agent/ebpf-core
make
cd go-loader && go build -o bin/carnot-ebpf-loader ./...
sudo ./bin/carnot-ebpf-loader -obj ../openssl_handshake.bpf.o -libssl /lib/x86_64-linux-gnu/libssl.so.3 -out ../../runtime.jsonl
```

## Acceptance
- `runtime.jsonl` contains **one line per handshake** with sni+groups+success.
- Loss < 1% in a 5k handshake run; note stats in WORKLOG.
- No crashes or hangs under load.
