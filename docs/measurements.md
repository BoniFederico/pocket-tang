# Measurements

All numbers below come from the reference board:

| Board property | Value |
|---|---|
| Chip | ESP32-D0WD-V3, silicon revision v3.1 |
| CPU | 240 MHz, dual core |
| Flash | 4 MB |
| Wi-Fi | 2.4 GHz WPA3 network, RSSI -65 to -71 dBm |

The runs used firmware 0.1.0-dev with the test profile, built with ESP-IDF v5.5.6 and Mbed TLS 3.6.7. They were collected with `tools/hil/pt_hil.py` on 2026-11-13. The client was a Windows PC on the same LAN, running Python `urllib` with one TCP connection per request. Raw results are in `hil-artifacts/hil-results.json` locally (not committed).

## Latency

`/rec` performs one P-521 scalar multiplication. `/adv` is served from the precomputed cache.

| Configuration | `/rec` p50 | `/rec` p95 | `/adv` p50 | `/adv` p95 |
|---|---|---|---|---|
| `esp_http_server`, Wi-Fi modem sleep (`WIFI_PS_MIN_MODEM`) | 653 ms | 1700 ms | 114 ms | 273 ms |
| `esp_http_server`, power saving off | 622 ms | 710 ms | 92 ms | 96 ms |
| **pt_server, power saving off (default)** | **573 ms** | **612 ms** | **26 ms** | **36 ms** |

The crypto worker measures the device-side time of the exchange itself:

| Big-number arithmetic | `/rec` crypto time (mean) | max |
|---|---|---|
| Hardware MPI (`CONFIG_MBEDTLS_HARDWARE_MPI=y`, default) | 531–546 ms | 565 ms |
| Software MPI (`bench-swmpi` profile) | 771 ms | 780 ms |

Hardware MPI acceleration makes the exchange 1.45× faster. The rest of the round trip, about 30 ms, is network, TCP and HTTP. Modem sleep adds up to one DTIM interval per request, so power saving is off by default (`CONFIG_PT_WIFI_PS_NONE`). It can be enabled for battery setups.

Key generation for two P-521 keys at first boot takes about 1.6 s.

## Memory

| Measurement | Value |
|---|---|
| Free heap after boot (pt_server, 6 connection buffers) | 146.7 KB |
| Free heap after 120 s + 180 s of stress | 146.6 KB (no leak) |
| Minimum free heap ever (heavy stress, lwIP buffers) | 106.7 KB |
| Largest free block | 110.6 KB |
| Crypto worker stack: size / free at high-water mark | 8192 / 4364 bytes |
| HTTP server task stack: size / free at high-water mark | 6144 / 3536 bytes |
| Static connection buffers (6 × 4 KB) | 24 KB |
| Application image | 0.91 MB (51 % of the 1.9 MB app partition free) |

### Final v1.0 firmware (setup mode, admin UI, captive DNS included)

Full 12-step HIL run on 2026-11-13 (`pt_hil.py all`, test profile):

| | |
|---|---|
| `/rec` round trip p50 / p95 | 572 / 611 ms (one outlier at 1.9 s during Wi-Fi activity) |
| `/rec` crypto on device (mean) | 541 ms |
| `/adv` round trip p50 / p95 | 29 / 38 ms |
| Free heap after boot (normal mode) | 128.7 KB |
| Free heap after 120 s stress / minimum ever | 125.2 KB / 99.9 KB |
| Crypto worker / HTTP task stack free at high-water mark | 4264 / 3164 bytes |
| Stress (6 threads + slowloris, 120 s) | 427 × 200, 223 correct 4xx, 0 connection errors |

The roughly 18 KB less free heap than the M2 measurements above comes from the setup/admin
features: the UI page buffer, the captive DNS, button and LED tasks.

## Robustness under load

`stress` runs 6–8 client threads for 120–180 s. One third send valid `/rec` requests, one third `/adv`, and one third hostile requests. The hostile requests are oversized bodies, malformed JWKs, unknown kids, very long URIs and wrong methods. One more thread keeps a slowloris connection that sends one header byte per second.

| Server | Valid answers in 120 s | Client-side connection errors | Device after test |
|---|---|---|---|
| `esp_http_server` | 12 (`200`) | 49 (resets, refused, timeouts) | alive, heap stable |
| **pt_server** | **415 (`200`) + 211 correct 4xx** | **0** | alive, heap stable |

`esp_http_server` reads request heads with blocking receives on its only task. The slowloris client therefore stalls everyone else (see [ADR-0004](adr/0004-own-http-server.md)). With 8 threads from one IP the per-peer cap refuses the extra connections immediately (fast connection errors on the client), while requests within the cap keep being served.

## Startup

| Phase | Time |
|---|---|
| Power-on to `PT_READY` (Wi-Fi associated, DHCP, keys loaded, server up) | 7–11 s |
| Of which: DHCP/association (dominant), key load with `d·G` validation of each key | ~0.5 s per stored key |
