# Hardening a device (Secure Boot, flash and NVS encryption)

!!! danger "Irreversible"
    Every step on this page burns eFuses inside the chip. **None of it can be undone.** A mistake
    can make the board permanently unusable. Practise on a spare board first. Keep your signing
    key safe and backed up: without it the device can never run new firmware.

!!! warning "No firmware updates after hardening (v1)"
    In flash-encryption **release** mode the serial bootloader cannot perform flash encryption
    any more. Espressif documents OTA as the update path, and serial updates would require
    pre-encrypting images with a copy of the on-chip key, which the default flow never reveals.
    Pocket Tang v1 has no OTA update (issue #15), so a hardened device keeps its firmware for
    life. Harden only a firmware version you are happy with.

Without hardening, anyone holding the board can dump the flash and read the Tang private keys
(see the [threat model](../design/threat-model.md)). Hardening protects against device theft.
It does not change anything about how the device works on the network.

## 1. Choose the profile for your chip

Identify the chip revision (read-only):

```sh
esptool --port /dev/ttyUSB0 chip-id
# Chip type: ESP32-D0WD-V3 (revision v3.1)
```

| Chip | Profile | Secure Boot |
|------|---------|-------------|
| ESP32 revision **≥ v3.0** | `secure-sbv2` | v2 (RSA-3072), key revocation possible |
| ESP32 revision **< v3.0** | `secure-esp32-sbv1` | v1 (ECDSA P-256), bootloader can never be updated |
| ESP32-C3, ESP32-S3 | `secure-sbv2` | v2 (RSA-3072) |

All profiles also enable flash encryption in **release** mode and **NVS encryption**, which
protects the key store and the Wi-Fi/admin secrets. They use the partition table
`partitions-secure.csv`, because the larger bootloader moves the partition table to `0x10000`.

## 2. Generate and protect the signing key

Generate the key on an offline machine and store it securely (for example an encrypted USB stick
plus a paper backup of the key's location). **Never commit it**: `*.pem` is in `.gitignore`.

```sh
cd firmware
# Secure Boot v2 (ESP32 rev >= 3, C3, S3)
espsecure generate-signing-key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
# Secure Boot v1 (ESP32 rev < 3)
espsecure generate-signing-key --version 1 secure_boot_signing_key_v1.pem
```

## 3. Build

Build with `PT_RELEASE_SIGNING=1`, so the build script refuses to create a throwaway key:

```sh
PT_RELEASE_SIGNING=1 tools/fw-build.sh esp32 secure-sbv2
```

Optionally first flash the same firmware **unhardened** (default profile), set it up, and check
that everything works.

## 4. First flash (this is the irreversible step)

1. Connect the board and erase it. **With Secure Boot enabled, `idf.py flash` does not flash
   the bootloader** (Secure Boot v1 and v2 alike). Flash it first with the exact command that
   `idf.py bootloader` prints. With Secure Boot v1 this is a one-time flash: the bootloader can
   never be changed afterwards. Then flash the partition table and the app:

   ```sh
   cd firmware
   idf.py -B ../build/fw-esp32-secure-sbv2 bootloader      # prints the bootloader flash command
   # run the printed esptool command, then:
   idf.py -B ../build/fw-esp32-secure-sbv2 -p /dev/ttyUSB0 flash monitor
   ```

2. On first boot the bootloader:
    - generates the flash-encryption key inside the chip and burns it (read-protected);
    - encrypts the bootloader, partition table, app and NVS-key partition in place (this takes
      about a minute: **do not remove power**);
    - burns the Secure Boot public-key digest (v2) or the bootloader key (v1);
    - disables JTAG (all chips). ESP32-C3/S3 switch the ROM download mode to *Secure Download
      Mode*. On the ESP32 the UART ROM download mode stays enabled by default, but in release
      mode it cannot read plaintext or flash unencrypted images. Disabling it permanently
      (`CONFIG_SECURE_UART_ROM_DL_MODE`, ESP32 rev ≥ 3) is possible but removes any serial
      recovery path.

3. The device reboots into setup mode as usual. Configure it through the setup access point.
   The Tang keys are then generated directly into encrypted NVS.

## 5. Verify

```sh
espefuse --port /dev/ttyUSB0 summary    # read-only
```

Check that `FLASH_CRYPT_CNT` (ESP32) or `SPI_BOOT_CRYPT_CNT` (C3/S3) is in the "enabled" state,
that `ABS_DONE_0`/`ABS_DONE_1` (ESP32 v1/v2) or the `SECURE_BOOT_EN` eFuse is set, and that JTAG
is disabled. A flash dump (`esptool read-flash`) must now contain only ciphertext.

## 6. Afterwards

- Factory reset still works and still destroys the keys (in encrypted NVS).
- Keep the signing key. Without it you cannot run any other firmware on the device.
- If the device is lost or stolen, rotate or retire its keys on your clients: bind to a new
  Tang server and remove the old binding with `clevis luks unbind`.

## References

- ESP-IDF Programming Guide: Secure Boot v2, Secure Boot (v1), Flash Encryption, NVS Encryption,
  for the respective chip, version v5.5.
- Espressif security advisories on fault injection for ESP32 revisions < v3.
