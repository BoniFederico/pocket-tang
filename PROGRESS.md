# Progress log

Resume point for autonomous work. Keep this file current: what is done, what is in flight, what is next.

## Status

| Milestone | Issue | State |
|-----------|-------|-------|
| M0 scaffolding, toolchain, CI skeleton, board verification | #1 | done (PR #8) |
| M1 portable core + host tests + clevis interop | #2 | done (PRs #11, #12) |
| M2 ESP32 platform layer + HIL + measurements | #3 | in review |
| M3 SoftAP provisioning, admin UI, button, LED | #4 | not started |
| M4 hardening profiles, threat model, fuzzing | #5 | not started |
| M5 docs site, README, v1.0.0 | #6 | not started |
| M6 MQTT + Home Assistant, v1.1.0 | #7 | not started |

## Environment (local, not in git)

- Build host: WSL Ubuntu 24.04 as root (`wsl -d Ubuntu -u root`), ESP-IDF v5.5.6 at `/opt/esp/idf`,
  tools at `/opt/esp/tools`, build directories under `/root/build/*` (repo mounted at
  `/mnt/c/Users/feder/pocket-tang`).
- Flashing/serial from Windows: board on `COM3`, `py -3.11 -m esptool`.
- Test Wi-Fi credentials in `.env.test` (git-ignored).

## Log

- 2026-11-13 â€” Environment surveyed; board verified (ESP32-D0WD-V3 rev v3.1, 4 MB flash); decided on
  ESP-IDF v5.5.6 + Mbed TLS 3.6 (ADR-0001); milestone issues #1â€“#7 created; scaffolding started.
- 2026-11-13 — M0 merged (#8); branch protection on `main` (required checks, linear history, squash only).
- 2026-11-13 — Recorded upstream tang 14 behaviour (fixtures in `core/tests/fixtures/tang14`,
  `docs/design/protocol-reference.md`). Core JSON/base64url merged (#11). Crypto backend, JWK, key store,
  protocol engine, HTTP parser, `tangd-host` and interop suite: 8 unit suites pass under ASan/UBSan,
  6 fuzzers clean, interop 54/54 incl. LUKS2 bind/unlock and byte-identical `/rec` replies.
  Deviation: private `d` in `/rec` requests rejected (ADR-0003).
- 2026-11-13 — M2: firmware serves Tang from the board (HIL: interop 31/31 over LAN, rotation and
  reboot persistence OK). Found and fixed a slowloris DoS in esp_http_server by replacing it with
  the portable `pt_server` (ADR-0004); measurements in `docs/measurements.md`.
