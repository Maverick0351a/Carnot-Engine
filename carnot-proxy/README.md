# Carnot Interop Lab (PQC Proxy)

**Purpose:** Interoperability testing and handshake proof for PQC/Hybrid TLS — **not** a FIPS-validated production crypto stack.

- Uses OpenSSL 3 and the Open Quantum Safe provider to offer PQC/hybrid key exchange groups.
- Attach PCAPs and server/client logs as **evidence** in assessments.
- Production traffic requiring FIPS validation must use vendor-supported, validated stacks.
