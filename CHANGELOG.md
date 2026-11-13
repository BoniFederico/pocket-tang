# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository scaffolding, contribution guidelines, security policy, issue and PR templates.
- ADR-0001 (ESP-IDF v5.5 with Mbed TLS 3.6) and ADR-0002 (own strict JSON parser).
- Hardware notes for the reference board.
- CI skeleton: formatting, static analysis, host build and tests, firmware build matrix.
- Core: strict, bounded, non-recursive JSON tokenizer and bounded JSON writer.
- Core: strict base64url codec (rejects padding and non-canonical encodings).
- libFuzzer harnesses for JSON and base64url, run for 60 s per target in CI.
- Core: crypto backend interface with an Mbed TLS 3.6 implementation (P-521 point/scalar checks,
  McCallum-Relyea exchange, deterministic ES512, SHA-1/224/256/384/512).
- Core: EC P-521 JWK parsing/serialisation, RFC 7638 thumbprints, libjose-compatible key permissions.
- Core: key store with tang-compatible rotation, versioned checksummed persistence format and import of
  upstream tang key files.
- Core: Tang protocol engine (`/adv`, `/adv/{kid}`, `/rec/{kid}`, `/version`) with a precomputed
  advertisement cache and upstream-identical status codes (see ADR-0003 for deliberate deviations).
- Core: strict bounded HTTP/1.1 request-head parser.
- Core: event-driven HTTP server on BSD sockets (`pt_server`) resistant to slow clients and
  connection floods; used by the firmware and `tangd-host` (ADR-0004).
- Core: web UI helpers (urlencoded forms, HTML escaping, PBKDF2 password verifiers, sessions with CSRF
  tokens, login back-off).
- Firmware: ESP32 platform layer serving Tang (NVS storage, crypto worker with bounded queue, Wi-Fi
  STA with WPA3, mDNS, SNTP, statistics), serial test console in the test profile only.
- Hardware-in-the-loop runner `tools/hil/pt_hil.py` and measurements in `docs/measurements.md`.
- Host harness `tangd-host` and `tools/interop.sh`: clevis round-trips, rotation, upstream cross-check,
  sss and LUKS2 bind/unlock; run in CI.
