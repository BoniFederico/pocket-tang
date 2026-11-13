# Hardware

## Reference development board

Facts verified with `esptool` on 2026-11-13 (read-only commands `chip-id` and `flash-id`):

| Property | Value |
|----------|-------|
| Board | Generic "ESP32 DevKit" (30-pin), ESP32-WROOM-32D module |
| Chip | ESP32-D0WD-V3, **silicon revision v3.1** (ECO3 or later) |
| Features | Wi-Fi, BT, dual core 240 MHz, Vref calibration in eFuse, coding scheme None |
| Crystal | 40 MHz |
| Flash | 4 MB (manufacturer 0x20, device 0x4016), 3.3 V, DIO/40 MHz safe defaults |
| USB-UART | Silicon Labs CP2102 (VID 10C4 / PID EA60); DTR→GPIO0, RTS→EN auto-reset circuit |
| Buttons | `BOOT` on GPIO0 (active low), `EN` (reset) |
| LED | On-board LED on GPIO2 (active high) — typical for this board family, confirmed during HIL bring-up |

Because the chip is revision **v3.1**, it supports **Secure Boot v2** (RSA-3072) and flash encryption with
the v3 key scheme. Boards with ESP32 revision < v3 only support Secure Boot v1; see the hardening guide.

> The development board used for testing is **never** fused, secure-booted or flash-encrypted. Those
> procedures are irreversible and are only validated by building the corresponding configuration profiles.

## Supported targets

| Target | Status | Notes |
|--------|--------|-------|
| `esp32` | reference, hardware tested | ESP32-WROOM-32D DevKit |
| `esp32c3` | CI build | RISC-V single core; Secure Boot v2 |
| `esp32s3` | CI build | Secure Boot v2 |
| Raspberry Pi Pico 2 W | future | requires a new platform layer only; the core is portable |

## Pin usage (esp32 default)

| Function | GPIO | Kconfig |
|----------|------|---------|
| BOOT button | 0 | `CONFIG_PT_BUTTON_GPIO` |
| Status LED | 2 | `CONFIG_PT_LED_GPIO` |
