# Carnot Agent — Go Loader (CO‑RE uprobes)

Memory‑safe userspace loader for OpenSSL uprobes + ringbuf using `github.com/cilium/ebpf`.

## Build
```bash
cd carnot-agent/loader-go
go build .
```

## Run
```bash
sudo ./loader-go -lib /lib/x86_64-linux-gnu/libssl.so.3 -obj ../ebpf-core/openssl_handshake.bpf.o
# Generate TLS traffic in another shell and observe JSONL events.
```
