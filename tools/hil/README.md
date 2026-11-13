# Hardware-in-the-loop (HIL) tests

`pt_hil.py` drives a real board attached over USB and the LAN. It runs locally on the developer
machine only (never in CI) and **never burns eFuses, enables flash encryption or Secure Boot**.

## Requirements

- The board on a serial port (Windows `COM3`, Linux `/dev/ttyUSB0`), with the usual DevKit
  auto-reset circuit (DTR → GPIO0, RTS → EN).
- Python 3.10+ with `pyserial` and `esptool` (`pip install pyserial esptool`).
- `clevis`, `jose`, `tang`, `jq`, `socat`, `curl` on Linux, or in WSL (Ubuntu) on Windows. The runner
  calls them through `wsl -d Ubuntu -u root` when it runs on Windows.
- `.env.test` at the repository root (git-ignored) with a **2.4 GHz** WPA2/WPA3 network:

  ```
  TEST_WIFI_SSID=...
  TEST_WIFI_PASSWORD=...
  ```

## Test firmware

HIL needs the **test profile**, which adds a serial console (`provision`, `stats`, `rotate`,
`reboot`, `factory-reset`). Release images never contain it; CI checks that.

```sh
tools/fw-build.sh esp32 test     # stages out/esp32-test/
```

## Running

```sh
py tools/hil/pt_hil.py --port COM3 all --build-dir out/esp32-test     # everything, wipes the board
py tools/hil/pt_hil.py --port COM3 provision                           # Wi-Fi from .env.test
py tools/hil/pt_hil.py --port COM3 --url http://192.168.1.214 latency -n 100
py tools/hil/pt_hil.py --port COM3 --url http://192.168.1.214 stress --seconds 300
py tools/hil/pt_hil.py --port COM3 --url http://192.168.1.214 interop
py tools/hil/pt_hil.py --port COM3 --url http://192.168.1.214 persistence
py tools/hil/pt_hil.py --port COM3 --url http://192.168.1.214 rotation
```

The `all` step sequence is:

1. Read-only chip identification (`esptool chip-id`).
2. Full flash erase, then flashing of the test build.
3. Provisioning over the serial console, followed by a reboot. It waits for the `PT_READY ip=...` line.
4. `/rec` and `/adv` latency (client side) and device statistics (crypto time, heap, stack high-water marks).
5. `tools/interop.sh --url`: clevis round-trip, `sss` across the board and a local upstream tangd, and the status-code matrix compared with upstream.
6. Stress: concurrent valid and hostile requests plus a slow client. The board must keep answering and its heap must stay stable.
7. Reboot persistence: the same thumbprints are advertised after a reboot.
8. Rotation: bind with clevis, rotate on the device, then check that the old binding still decrypts.

Results go to `hil-artifacts/` (git-ignored): `hil-results.json`, `serial.log` (the Wi-Fi password is
redacted) and `interop.log`.

## Button simulation

On the DevKit auto-reset circuit, asserting DTR while RTS is released pulls GPIO0 low, which is
electrically the same as holding BOOT. `Board.set_boot_button()` uses this to test medium and long
presses without a human (milestone M3). Toggling RTS resets the chip through EN.

## What still needs a human

- Watching LED patterns. The firmware also logs every LED state change on the console.
- Joining the setup SoftAP from a phone and checking that the captive portal pops up.
