# Golden Dataset & Performance Methodology

**Goal:** Credible overhead measurements for the eBPF agent at realistic loads.

## Workload Mix
- TLS versions: 1.2 (legacy), 1.3 (default)
- Key exchange: X25519, P-256, Hybrid (X25519+ML-KEM-768)
- Session resumption ratio: 30–60%
- Traffic: 70% short connections, 30% long-lived

## Procedure
1. **Baseline:** measure CPU and latency histograms without the agent.
2. **Agent On:** enable handshake-only uprobes; sample at 100% then 50%.
3. **Metrics:** process CPU, per-core utilization, 95/99p handshake latency.
4. **Repeat:** across variants (classical vs hybrid, resumption on/off).

## Tools
- `wrk` or `hey` with `Connection: close` to force handshakes.
- `h2load` for HTTP/2 TLS 1.3.
- Capture `perf stat` and `pidstat` for CPU.

## Reporting
- Publish delta CPU (%) and added latency (ms) for each mix.
- Include agent drop counters (ring buffer drops) and sampling settings.
