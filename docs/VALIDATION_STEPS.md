# Validation Steps
- Windows ETW: build & run SChannelETW, generate TLS traffic, convert with tools/ingest/etw_jsonl_to_bom.py
- Java JFR: run with aegisq_crypto.jfc, print events, convert with tools/ingest/jfr_to_bom.py
- QUIC/ECH: capture with Wireshark, note SNI obfuscation; rely on endpoint telemetry
- PQC lab: start docker-compose and verify hybrid groups with s_client (interop only)
