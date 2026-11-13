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

## MQTT and Home Assistant

Firmware 1.1.0-dev, MQTT over TLS (`mqtts://`, private CA, user/password) to a mosquitto 2.1.2
broker on the LAN, 2026-11-13. Every successful or refused recovery publishes an event and
(coalesced to at most one per second) a state message.

| 150 recoveries | `/rec` p50 | `/rec` p95 | crypto on device (mean) | free heap |
|---|---|---|---|---|
| MQTT off | 584.8 ms | 671.4 ms | 546.8 ms | 112.6 KB |
| MQTT on (TLS, connected) | 584.5 ms | 647.7 ms | 543.8 ms | 88.6 KB |
| MQTT on, broker unreachable (100 recoveries, reconnecting) | 578.9 ms | 657.2 ms | 538.5 ms | 92.6 KB |

The differences are within run-to-run noise, so the integration does not slow down recovery.
All 150 events were delivered (150/150) and no 503 was returned.

The TLS session cost about 69 KB of heap (112.6 KB → 43.9 KB free) with ESP-IDF's default static record buffers. Enabling
`CONFIG_MBEDTLS_DYNAMIC_BUFFER` (plus freeing handshake-only data and a 4 KB output record)
brought the connected cost down to about 24 KB.

An early version queued messages with `esp_mqtt_client_enqueue()`. Under a burst of recoveries
the outbox drained more slowly than it filled, and only 77 of 150 events arrived. Publishing
directly from the low-priority publisher task (`esp_mqtt_client_publish()`), with state updates
coalesced, fixed it. The Tang path itself only ever does a non-blocking queue send.

| Other checks (HIL `mqtt` step) | Result |
|---|---|
| Discovery: all 12 components, unique ids, availability topic | pass |
| Re-discovery on `homeassistant/status` = `online` | pass |
| Lock switch from MQTT | `/rec` 403 when ON, 200 when OFF |
| Last will on abrupt reset | `offline` after 12 s |
| Restart button | device restarts |
| No private key material in any message | pass |

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
