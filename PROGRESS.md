# Progress log

Resume point for autonomous work. Keep this file current: what is done, what is in flight, what is next.

## Status

| Milestone | Issue | State |
|-----------|-------|-------|
| M0 scaffolding, toolchain, CI skeleton, board verification | #1 | in progress |
| M1 portable core + host tests + clevis interop | #2 | not started |
| M2 ESP32 platform layer + HIL + measurements | #3 | not started |
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

- 2026-11-13 — Environment surveyed; board verified (ESP32-D0WD-V3 rev v3.1, 4 MB flash); decided on
  ESP-IDF v5.5.6 + Mbed TLS 3.6 (ADR-0001); milestone issues #1–#7 created; scaffolding started.
