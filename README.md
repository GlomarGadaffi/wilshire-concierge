# esp-secure-transport

permissively-licensed (MIT/PD) secure-transport stack for ESP-IDF. **currently paused** in favor of its pragmatic sibling glossh, but documented here for reference.

## what's built

crypto primitives verified on hardware (T-ETH-ELITE / ESP32-S3):
- X25519, IETF ChaCha20-Poly1305, SHA-256, HKDF, Ed25519 (via TinySSH's tinynacl + hand-written ChaCha20)
- **TLS 1.3 key schedule** (RFC 8446 §7.1) — early/handshake/master secrets, traffic keys/ivs, finished keys. anchored to RFC 8448 published constants.
- **TLS 1.3 record layer** (RFC 8446 §5.2/5.3) — TLSCiphertext framing, per-record nonce, AEAD seal/open.
- **SSH server** — TinySSH port on port 22 (shell/exec non-functional on ESP due to execve stub).

on-device self-test passes 26/26 checks (see `components/glo_mtls/src/glo_selftest.c`).

## what's not done

- handshake messages (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished)
- state machine / `glo_mtls_connect` wrapper
- interop testing (needs a RawPublicKey TLS 1.3 peer)

## why paused

original goal: "avoid Apache-2.0 / mbedTLS" for a purely MIT/PD stack. turns out mbedTLS is **already in every ESP-IDF image** (esp_tls, HTTPS, Wi-Fi enterprise, PSA API), so avoiding it buys no smaller binary and no reduced license surface. for the practical goal (clean SSH console), glossh (littlessh) on PSA Crypto is simpler, hardware-accelerated, and OpenSSH-interoperable.

esp-secure-transport retains value if a genuinely pure zero-Apache stack is later required (non-ESP-IDF target, hard licensing constraint) or specifically for tiny raw-public-key (RFC 7250) mTLS, which mbedTLS supports poorly. the work here is correct and resumable.

## structure

- `components/glo_mtls/` — crypto, key schedule, record layer (the viable foundation)
- `components/tinyssh` — TinySSH port
- `tools/` — auxiliary build/test scripts

see STATUS.md for detailed technical breakdown.
