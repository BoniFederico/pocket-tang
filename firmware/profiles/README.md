# Configuration profiles

Apply a profile on top of the defaults with `SDKCONFIG_DEFAULTS`, e.g.

```sh
idf.py -C firmware -B build/esp32-secure -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;profiles/sdkconfig.secure-sbv2.defaults" set-target esp32 build
```

Profiles are added in milestone M4 (security) and M6 (MQTT). The `test` profile enables the serial test
console used by the hardware-in-the-loop runner and must never be used for release images.
