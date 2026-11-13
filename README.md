# Pocket Tang

[![CI](https://github.com/BoniFederico/pocket-tang/actions/workflows/ci.yml/badge.svg)](https://github.com/BoniFederico/pocket-tang/actions/workflows/ci.yml)
[![Firmware](https://github.com/BoniFederico/pocket-tang/actions/workflows/firmware.yml/badge.svg)](https://github.com/BoniFederico/pocket-tang/actions/workflows/firmware.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A [Tang](https://github.com/latchset/tang) server for ESP32 microcontrollers: network-bound disk
encryption (Clevis/LUKS) on a board that costs less than a coffee.

**Tang in three lines.** [Network-Bound Disk Encryption](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/configuring-automated-unlocking-of-encrypted-volumes-using-policy-based-decryption_security-hardening)
lets a LUKS volume unlock automatically only while it can reach a Tang server on your network. Tang never
sees or stores the disk key: the client derives it through the McCallum-Relyea key exchange, so a stolen
disk (or a stolen Tang server) alone reveals nothing. [Clevis](https://github.com/latchset/clevis) is the
client that binds LUKS volumes to one or more Tang servers.

**Why this project.** Upstream Tang is a tiny service, yet it usually ends up on a Raspberry Pi or a VM
that must be kept patched and powered. Pocket Tang runs the same protocol, wire-compatible with the
upstream Clevis client, on a $3 ESP32 that boots in a second, needs no operating system and sips power.

> **Status:** under active development; not yet released. Follow the milestone issues.

## Features (planned for v1.0.0)

- Wire-compatible `GET /adv`, `GET /adv/{kid}`, `POST /rec/{kid}` with ES512 / ECMR keys on P-521,
  thumbprints and key-rotation semantics identical to upstream Tang
- Portable core (no ESP-IDF dependency) tested on Linux with ASan/UBSan, libFuzzer and the real `clevis`
- Captive-portal first-boot setup, mDNS, authenticated admin page with key rotation
- BOOT button: medium press → setup mode, long press → factory reset (with LED feedback)
- Hardening profiles: Secure Boot (v1/v2), flash encryption, NVS encryption
- Optional MQTT / Home Assistant integration (v1.1.0)

## Supported boards

| Target | Status |
|--------|--------|
| ESP32 (ESP32-WROOM-32 DevKit, reference board) | hardware tested |
| ESP32-C3 | CI build |
| ESP32-S3 | CI build |
| Raspberry Pi Pico 2 W | future platform layer |

## Documentation

- [Hardware](docs/hardware.md)
- [Development setup](docs/dev-setup.md)
- [Architecture decision records](docs/adr/README.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
