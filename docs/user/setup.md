# First setup and admin page

## Setup mode

The device is in **setup mode** when it has no Wi-Fi configuration yet (first boot or after a
factory reset), or when you hold the BOOT button for 3–10 seconds (see
[Button and reset](reset.md)). In setup mode:

- it opens a WPA2 access point `PocketTang-XXXX`, where `XXXX` are the last digits of the MAC
  address;
- its password is random and per device. It is printed on the serial console at **every** boot:

    ```text
    I (1530) pocket-tang: setup access point password: k7mnp3qrs8tv
    W (1625) pocket-tang: PT_SETUP_AP ssid=PocketTang-A1B2 password=k7mnp3qrs8tv url=http://192.168.4.1/admin
    ```

    Write it down or stick it on the device. It changes only after a factory reset.
- phones and laptops show a captive-portal page (or browse to `http://192.168.4.1/admin`);
- the LED blinks slowly (1 Hz);
- if the device was already configured, it **stays connected to your network and keeps serving
  Tang** while in setup mode, so bound machines continue to unlock;
- after 15 minutes without changes (and no client on the access point), a configured device
  leaves setup mode by itself.

!!! note "Why the password is on the serial console"
    Reading the serial console requires physical access to the device. Someone within radio range
    can see the access point, but cannot join it or change anything without the password.

## The setup form

| Field | Notes |
|-------|-------|
| Wi-Fi network | 2.4 GHz only (ESP32 limitation). WPA2 or WPA3 networks. The list shows nearby networks. The current network is pre-filled. |
| Wi-Fi password | 8–63 characters. Leave empty to keep the stored one (same network). |
| Hostname | `name.local` via mDNS, 1–32 letters, digits or `-`. |
| Tang HTTP port | Default 80. Clevis URLs must include it when it is not 80. |
| Admin password | 8–64 characters, required on first setup. Stored as a salted PBKDF2-SHA256 hash. |
| Allow the admin page on the LAN | Off by default. See below. |

**Save and restart** stores the settings and reboots into normal mode.

## The admin page

On the setup access point the admin page is always at `http://192.168.4.1/admin`. If you enabled
*Allow the admin page on the LAN*, it is also at `http://<hostname>.local/admin` in normal mode.

It shows:

- status: IP address, Wi-Fi signal, uptime, number of recoveries, last client;
- the key thumbprints (SHA-256): the **signing** thumbprint is the `thp` for Clevis;
- actions: **Rotate keys**, **Delete rotated keys**, **Lock/Unlock recovery**, **Restart**,
  **Factory reset** (type `RESET` to confirm), **Log out**;
- the configuration form.

The page never shows or exports private keys.

!!! warning "LAN admin runs over plain HTTP"
    An attacker who can intercept traffic on your LAN could capture the admin password while you
    log in. Enable LAN admin only on a network you trust, or administer the device through the
    setup access point, which is WPA2-encrypted. See the [threat model](../design/threat-model.md).

Login protections: session cookie (`HttpOnly`, `SameSite=Strict`, ends after 10 minutes of inactivity), CSRF
token in every form, and an increasing lock-out after repeated wrong passwords (5 s, 10 s, 20 s …
up to 5 minutes).

## Recovery lock

**Lock recovery** makes every `/rec` request fail with HTTP 403, while `/adv` keeps working.
Bound machines then fall back to their passphrase. Use it if a bound machine is stolen while
the thief could still be on your network. The lock persists across reboots.
