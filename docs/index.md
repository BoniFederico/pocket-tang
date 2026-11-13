# Pocket Tang

**A [Tang](https://github.com/latchset/tang) server for ESP32 microcontrollers**: network-bound disk
encryption (NBDE) for Clevis/LUKS on a board that costs a few euros.

Network-Bound Disk Encryption lets an encrypted Linux disk unlock automatically, but only while
it can reach a Tang server on your network. The Tang server never sees the disk key. A stolen
disk, taken away from your network, stays locked.

Pocket Tang speaks the same protocol as upstream `tangd`, byte for byte where it matters. It is
tested against the real `clevis` and `jose` tools and cross-checked against upstream tang on
identical keys. It runs on an ESP32 that boots in seconds, needs no operating system and draws
less than half a watt.

<div class="grid cards" markdown>

- **[Getting started](user/getting-started.md)**: flash, set up, bind a disk in 10 minutes.
- **[Web flasher](flasher.md)**: install from the browser, no toolchain needed.
- **[Binding disks with Clevis](user/clevis.md)**: LUKS, initramfs, multiple Tang servers.
- **[Design notes](design/index.md)**: how it works, explained like lecture notes.

</div>

## Features

- Wire-compatible `GET /adv`, `GET /adv/{kid}` and `POST /rec/{kid}`. ES512 and ECMR keys on
  P-521, the same thumbprints (S1…S512) and the same key-rotation semantics as upstream tang.
- Portable C17 core with no ESP-IDF dependency, tested on Linux under ASan/UBSan. Seven libFuzzer
  targets. Interop suite with clevis, including LUKS2 bind/unlock.
- First-boot setup over a WPA2 access point with a captive portal. mDNS name. Password-protected
  admin page with key rotation and a recovery lock.
- BOOT button: hold 3 s for setup mode, hold 10 s for factory reset, with LED feedback.
- Hardening profiles: Secure Boot (v1/v2), flash encryption, NVS encryption.
- Measured on real hardware: `/rec` in about 0.57 s, `/adv` in about 26 ms, stable heap under
  stress. See [measurements](measurements.md).

!!! warning "A factory reset breaks every binding"
    The Tang keys live only on the device. A factory reset (BOOT held for 10 s, or the admin
    page) destroys them, and **every disk bound to this Pocket Tang stops unlocking
    automatically**. Keep the LUKS passphrase, or bind to more than one Tang server.

## Supported boards

| Target | Status |
|--------|--------|
| ESP32 (ESP32-WROOM-32 DevKit, reference board) | hardware tested |
| ESP32-C3 | built in CI |
| ESP32-S3 | built in CI |
| Raspberry Pi Pico 2 W | planned (new platform layer only) |
