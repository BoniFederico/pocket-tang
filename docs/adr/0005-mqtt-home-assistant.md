# ADR-0005: MQTT / Home Assistant integration that cannot slow down Tang

- Status: Accepted
- Date: 2026-11-13
- Issue: #7

## Context

Users want to see unlock activity in Home Assistant, and to have a remote "lock" switch. The
integration must never block or slow down `/rec`, must not leak key material, must support TLS,
and must be optional: a Kconfig switch, plus a runtime toggle that is off by default.

## Decisions

1. **Transport and discovery.** ESP-IDF's `esp-mqtt` client with Home Assistant
   **device-based discovery**: one `homeassistant/device/<id>/config` message with `dev`, `o`
   and `cmps`, as documented by Home Assistant (2026.11). Discovery is not retained. It is re-sent
   on every connect and when `homeassistant/status` becomes `online`, after a random delay of
   0.2–1.7 s, following the Home Assistant recommendation that warns against ghost entities from
   retained discovery.
2. **Isolation from the Tang path.** The crypto worker calls a listener that does one
   `xQueueSend(..., 0)` into an 8-entry queue and returns. When the queue is full the event is
   dropped (counted), never waited for. Publishing happens on a priority-1 publisher task, and
   esp-mqtt runs at priority 2. Both are below the HTTP server (5) and the crypto worker (6). The
   admin page only sets a flag, which the publisher task acts on.
3. **Direct publish instead of the outbox.** `esp_mqtt_client_enqueue()` was tried first. Under a
   burst of recoveries the outbox drained more slowly than it filled, and 73 of 150 events were
   lost. The publisher task now uses the blocking `esp_mqtt_client_publish()`, which is
   acceptable because nothing time-critical runs on that task, and coalesces state updates to at
   most one per second.
4. **TLS.** `mqtts://` with the ESP-IDF certificate bundle by default, or a user-supplied CA PEM
   stored in NVS for private LAN brokers. There is no "skip verification" option. mbedTLS dynamic
   record buffers are enabled, which brought the connected TLS cost from about 69 KB down to
   about 24 KB of heap.
5. **Entities.** An event entity (`unlock` / `denied`, without a device class, because Home
   Assistant defines no lock class for events); sensors (last unlock as an epoch timestamp
   converted with `as_datetime`, last client, two `total_increasing` counters, RSSI, uptime,
   firmware version, and the two thumbprints as diagnostics); a lock switch (persisted, the same
   flag as the admin page); and a restart button (`device_class: restart`).
6. **What is never published.** Private keys, the admin password and Wi-Fi credentials. Only
   public thumbprints, counters and addresses. The HIL test asserts that no message contains
   a JWK private member.

## Consequences

- Measured on the board: `/rec` p50 584.5 ms with MQTT over TLS versus 584.8 ms without, and
  150 of 150 events delivered (see `docs/measurements.md`).
- About 24 KB of extra heap while connected over TLS, and about 0.2 MB of flash for the client
  and the certificate bundle.
- Whoever can publish on the device's command topics can lock recoveries or restart the device,
  so the broker must enforce authentication and ACLs (documented).
