# Troubleshooting

## The disk does not unlock at boot

1. **Name resolution**: the initramfs cannot resolve `*.local`. Use the device IP (DHCP
   reservation) in the Clevis URL.
2. **Network in early boot**: Fedora/RHEL need `rd.neednet=1 ip=dhcp` (or your interface) on the
   kernel command line. Debian/Ubuntu need `clevis-initramfs` and `update-initramfs -u`.
3. **Device reachable?** From another machine: `curl -s -o /dev/null -w '%{http_code}' http://<ip>/adv`
   must print `200`.
4. **Recovery locked?** The admin page shows *Recovery lock: LOCKED*. `/rec` then answers 403.
5. **Keys changed?** After a factory reset or after deleting rotated keys, old bindings cannot
   unlock. `clevis luks report -d <dev> -s <slot>` tells you.
6. Test outside the boot path: `sudo clevis luks unlock -d <dev> -n test`.

## `clevis encrypt` says the advertisement is untrusted

Pass the signing thumbprint with `"thp"` (admin page → Keys → signing). Without it, clevis shows
the advertised keys and asks for confirmation.

## The device does not join Wi-Fi

- ESP32 supports **2.4 GHz only**. Dual-band routers with one SSID are fine. 5-GHz-only SSIDs are
  not.
- WPA2 and WPA3-Personal are supported. Open and WEP networks are refused on purpose.
- The serial log shows `disconnected (reason N)`: 15 (4-way handshake timeout), 202
  (authentication failed) or 204 (handshake timeout) usually mean a wrong password. 201 means the
  SSID was not found (out of range, or 5 GHz only).
- Enter setup mode (hold BOOT 3–10 s) and correct the settings.

## I lost the setup access-point password

It is printed on the serial console at every boot. Connect USB and open a serial monitor at 115200
baud (the [web flasher](../flasher.md) has *Logs & Console*).

## I forgot the admin password

Once an admin password is set, the setup form also requires it, so the button alone does not
help. Only a factory reset clears it, and a factory reset **also destroys the Tang keys**. Store
the admin password in your password manager. Tang itself keeps working without it: the admin
password only protects the admin page.

## The LED blinks three times repeatedly

The stored keys failed validation (for example, flash corruption). The device refuses to serve
rather than silently generate new keys. Only a factory reset recovers it, and existing bindings
are then lost.

## Serial console shows `worker busy, 503`

More recoveries arrived at once than the queue holds (4). Clients retry, and clevis treats it as
a temporary failure. On a home network this indicates a misbehaving client.
