# Button, setup mode and factory reset

The BOOT button (GPIO0 on ESP32 DevKits) works while the device is running. Holding it while
plugging in or pressing EN starts the chip's download mode instead, which is harmless: just
reset again.

| Hold time | LED while holding | Action on release |
|-----------|-------------------|-------------------|
| < 3 s | unchanged | nothing |
| 3–10 s | very fast blink | **setup mode**: setup access point on, keys kept, Tang keeps serving |
| ≥ 10 s | solid on | **factory reset**: keys and settings erased, then setup mode |

The action happens on release, so the LED tells you what will happen before you let go.

## LED patterns

| Pattern | Meaning |
|---------|---------|
| fast blink (5 Hz) | connecting to Wi-Fi |
| off, short flicker on activity | normal operation |
| slow blink (1 Hz) | setup mode |
| very fast blink | button held 3–10 s |
| solid | button held ≥ 10 s |
| three short blinks, repeating | keys unavailable (stored keys invalid): factory reset needed |

The serial console logs every LED change (`PT_LED setup`, `PT_LED hold-reset`, …), which is
useful when the LED is hard to see.

## Factory reset

!!! danger "A factory reset breaks every Clevis binding to this device"
    The Tang keys exist only on the device. After a factory reset, disks bound to it **will not
    unlock automatically any more**. Unlock them with their passphrase and bind them again, or
    unbind the dead slot with `clevis luks unbind`.

A factory reset erases the Tang keys (active and rotated), the Wi-Fi settings, the admin password
and the setup access-point password, which is renewed. It is available from the button (≥ 10 s)
and from the admin page (type `RESET`). The device restarts in setup mode and generates new keys.
