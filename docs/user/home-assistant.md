# Home Assistant (MQTT)

Pocket Tang can publish its activity to an MQTT broker with
[Home Assistant MQTT discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery).
The device then shows up in Home Assistant with no YAML to write. The integration is
**optional and off by default**.

## Enable it

1. Make sure Home Assistant has the MQTT integration and a broker, for example the Mosquitto
   add-on.
2. Open the setup/admin page ([First setup](setup.md)), tick **Publish events and sensors to an
   MQTT broker**, then enter:
    - **Broker URI**: `mqtts://broker.lan:8883` (TLS, recommended) or `mqtt://broker.lan:1883`;
    - **MQTT user / password**, if your broker requires them.
3. For a broker with a private certificate authority, which is typical on a LAN, paste the CA
   certificate (PEM) in **MQTT broker CA certificate** on the admin page. Without it the device
   verifies the broker against the public certificate bundle, so public CAs such as
   Let's Encrypt work without any extra step.
4. Save and restart.

The broker certificate and its host name or IP are always verified, and a connection with a
certificate that does not verify is refused. Over plain `mqtt://` the password travels
unencrypted, and the device logs a warning.

## What appears in Home Assistant

One device, named after the hostname, with:

| Entity | Type | Notes |
|--------|------|-------|
| Recovery | event | `unlock` or `denied`; attributes `client`, `kid`, `status` |
| Last unlock | sensor (timestamp) | needs SNTP time (`pool.ntp.org`) |
| Last client | sensor | IP address of the last successful recovery |
| Unlocks | sensor (total increasing) | since boot |
| Denied | sensor (total increasing) | refused `/rec` requests since boot |
| Wi-Fi signal | sensor (dBm, diagnostic) | |
| Uptime | sensor (duration, diagnostic) | |
| Firmware version | sensor (diagnostic) | |
| Signing / exchange key thumbprint | sensors (diagnostic) | public SHA-256 thumbprints only |
| Recovery lock | switch | **ON** makes every `/rec` fail with 403; persisted across reboots |
| Restart | button | restarts the device |

The device is *unavailable* in Home Assistant when it loses the broker connection (MQTT last
will). It re-announces itself whenever Home Assistant restarts (`homeassistant/status` →
`online`).

### Automation example: alert on a denied recovery

```yaml
automation:
  - alias: "Tang: recovery denied"
    trigger:
      - platform: state
        entity_id: event.pocket_tang_recovery
    condition:
      - condition: template
        value_template: "{{ trigger.to_state.attributes.event_type == 'denied' }}"
    action:
      - service: notify.mobile_app_phone
        data:
          message: >
            Pocket Tang refused a recovery from
            {{ trigger.to_state.attributes.client }} (HTTP {{ trigger.to_state.attributes.status }}).
```

Adjust the entity id to what Home Assistant created for your device.

## Topics

With `<id>` = `pockettang_<MAC address>`:

| Topic | Content |
|-------|---------|
| `homeassistant/device/<id>/config` | device discovery (not retained; re-sent on HA birth) |
| `pocket-tang/<id>/availability` | `online` / `offline` (retained, last will) |
| `pocket-tang/<id>/event` | `{"event_type":"unlock","client":"192.168.1.20","kid":"…","status":200}` |
| `pocket-tang/<id>/state` | `{"rssi":-68,"uptime_s":106,"unlocks":1,"denied":0,"last_unlock":1794593436,"last_client":"…","version":"…"}` |
| `pocket-tang/<id>/keys` | `{"signing":"<thumbprint>","exchange":"<thumbprint>"}` |
| `pocket-tang/<id>/lock` | `ON` / `OFF` (retained); command topic `…/lock/set` |
| `pocket-tang/<id>/restart` | command topic, payload `PRESS` |

## Privacy and security

- No key material is ever published: only public thumbprints, counters and addresses. The
  hardware-in-the-loop test asserts that no message contains a private key member.
- Anyone who can publish to `pocket-tang/<id>/lock/set` or `…/restart` on your broker can lock
  recoveries or restart the device. Protect the broker with authentication and ACLs, as you would
  for any other device.
- The integration runs on low-priority tasks and never makes a recovery wait. Measurements are in
  [Measurements](../measurements.md#mqtt-and-home-assistant).
