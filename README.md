# GloSSH

**Permissively-licensed secure transport for ESP-IDF.**

GloSSH is a de-wolfed secure-transport stack for ESP32 / ESP-IDF projects. It
exists because the embedded SSL/SSH options are awkward: wolfSSL/wolfSSH are
GPLv2-or-commercial, and even the permissive default (mbedTLS) is Apache-2.0.
GloSSH assembles an **MIT / public-domain** alternative from battle-tested,
non-copyleft sources — no GPL, no commercial license, no Apache NOTICE chain.

It was extracted from the [drawbridge](https://github.com/EC-SH/drawbridge)
edge-PBX project to replace its `wolfSSH` / `wolfSSL` dependency.

## What's in here

| Component | Role | License | Status |
|-----------|------|---------|--------|
| `components/dropbear` | SSH server/client (full-featured) + bundled LibTomCrypt/LibTomMath | MIT-style + public domain | ESP-IDF port, working |
| `components/tinyssh`  | Minimal SSH server (used by the example) | Public domain | ESP-IDF port, working |
| `components/glo_mtls` | Outbound mutual-TLS 1.3 client on LibTomCrypt primitives | MIT | **scaffold / roadmap** |
| `main/`               | Example app: Wi-Fi bring-up + TinySSH server | MIT | example |

Two SSH backends ship: **TinySSH** (tiny, modern, NaCl-lineage crypto) and
**Dropbear** (full-featured). Both define `ssh_task()`; only the one listed in
`main/CMakeLists.txt` `REQUIRES` is linked. The example uses TinySSH.

## Roadmap: the mTLS client

The remaining wolf replacement is the **TLS** surface. `glo_mtls` is a
deliberately narrow, client-only, version-pinned, AEAD-only TLS 1.3 client
built on the public-domain crypto already vendored with Dropbear — sized for
exactly what drawbridge needs (outbound mTLS to an operator-owned media
anchor), not a general-purpose TLS library. See
[`components/glo_mtls/include/glo_mtls.h`](components/glo_mtls/include/glo_mtls.h).

> Scope discipline: a version-pinned client that validates the peer chain + SAN
> is safe to hand-roll on vetted primitives. Server-side / general-purpose TLS
> is out of scope — reach for BearSSL (MIT) if you ever need it.

## Build (example)

```sh
idf.py set-target esp32s3
# edit main/main.c: set EXAMPLE_STA_SSID / EXAMPLE_STA_PASSWORD / EXAMPLE_AUTHORIZED_KEY
idf.py build flash monitor
```

The example brings up Wi-Fi (SoftAP + STA), provisions an authorized SSH public
key into NVS, and starts the TinySSH server. **All credentials in `main.c` are
placeholders** — replace them before flashing; never commit real ones.

## Licensing

GloSSH's original work (port glue, build system, `glo_mtls`) is **MIT** — see
[LICENSE](LICENSE). Vendored third-party source keeps its own permissive /
public-domain terms; nothing here is copyleft. See [NOTICE](NOTICE) and
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

The upstream trees were **vendored flat** (copied source, not submodules) from a
working ESP-IDF port, so they may carry local compatibility edits. To pull
upstream security patches, diff against the tagged upstream releases listed in
THIRD-PARTY-LICENSES.md.
