# Flashing

## Release images

Every [GitHub release](https://github.com/BoniFederico/pocket-tang/releases) contains, per
target:

| File | Content | Flash offset |
|------|---------|--------------|
| `pocket-tang-vX.Y.Z-<target>.bin` | merged image (bootloader + partition table + app) | `0x0` |
| `pocket-tang-vX.Y.Z-<target>-app.bin` | application only (to update an existing device) | `0x20000` |
| `SHA256SUMS` | checksums of all files | |

Verify the download:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

## Browser (recommended)

The [web flasher](../flasher.md) uses ESP Web Tools and works in Chrome, Edge and Opera on desktop
operating systems. It selects the right image for the detected chip.

## esptool

```sh
pip install esptool
# first installation (erases the flash: keys and settings are lost!)
esptool --chip esp32 --port /dev/ttyUSB0 erase-flash
esptool --chip esp32 --port /dev/ttyUSB0 write-flash 0x0 pocket-tang-v1.0.0-esp32.bin
# update keeping keys and settings: write only the application
esptool --chip esp32 --port /dev/ttyUSB0 write-flash 0x20000 pocket-tang-v1.0.0-esp32-app.bin
```

On Windows the port is `COMx`. On Linux, add your user to the `dialout` group. Boards with a
CP210x or CH340 USB-UART chip may need the vendor driver on Windows.

!!! warning "Erasing destroys the keys"
    `erase-flash`, and writing a merged image over an existing installation, wipes the Tang keys.
    Bound disks will no longer unlock automatically. To update, write only the `-app.bin` image
    at `0x20000`.

## Building from source

See [Development](../dev-setup.md). In short, with ESP-IDF v5.5.6:

```sh
tools/fw-build.sh esp32        # stages out/esp32-default/ with merged image and checksums
```
