# ADR-0004: Own event-driven HTTP server instead of esp_http_server

- Status: Accepted
- Date: 2026-11-13
- Issue: #3

## Context

The first ESP32 platform layer used ESP-IDF's `esp_http_server`. Hardware-in-the-loop stress
testing showed that a single client that sends a request head slowly ("slowloris", one byte
per second) stalls the whole server. `esp_http_server` runs one task and reads a request head
with blocking `recv()` calls, each bounded only by `recv_wait_timeout`. While it waits on the
slow socket no other client is served. In a 120 s test only 12 requests succeeded and 49 client
connections failed. A Tang server must keep answering legitimate clients when someone on the
LAN misbehaves.

## Options considered

1. **Keep esp_http_server and add a watchdog** that calls `shutdown()` on sockets with an
   incomplete request older than N seconds. This limits each stall to N seconds, but an attacker
   who reconnects can still stall the server most of the time.
2. **Keep esp_http_server with multiple instances or ports**: more RAM, and the same flaw.
3. **Write a small event-driven server** (`core/net/pt_server.c`, about 400 lines). It uses
   non-blocking sockets and `select()`, a total deadline per request, bounded connections with a
   per-peer cap and eviction of the oldest connection, the fuzzed `pt_http` head parser, and one
   request per connection.

## Decision

Option 3. The server uses only BSD sockets and `clock_gettime()`. It builds unchanged on Linux,
where `tangd-host` uses it and the unit tests run slowloris, flood and eviction scenarios under
ASan/UBSan, and on ESP-IDF/lwIP. The future Raspberry Pi Pico port will need its own HTTP server
anyway, so this also removes a platform dependency.

## Consequences

- Measured on the board: `/adv` p50 dropped from 92 ms to 26 ms, `/rec` p50 from 622 ms to
  573 ms, and the stress test went from 12 to 415 successful responses with zero connection
  errors (see `docs/measurements.md`).
- About 24 KB of static RAM for connection buffers (6 × 4 KB). Free heap is still about 146 KB.
- Requests are handled synchronously on the server task. A `/rec` (about 0.55 s of crypto)
  delays other complete requests but cannot be used to hold connections, because incomplete
  requests time out independently. No keep-alive and no chunked encoding, which Tang clients
  do not need.
