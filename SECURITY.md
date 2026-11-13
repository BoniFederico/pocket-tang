# Security Policy

Pocket Tang is a Tang server: it takes part in protecting LUKS disk-encryption keys. Please treat any
weakness seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest minor release (`1.x`) | yes |
| older releases | no |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting on this repository
(*Security* tab → *Report a vulnerability*). You should receive an acknowledgement within 7 days.
If you prefer e-mail, contact the maintainer through the address on their GitHub profile.

Please include: firmware version (`GET /version`), board/target, reproduction steps and, where
possible, a proof of concept. Please give us a reasonable time to ship a fix before disclosure.

## Scope and threat model

The threat model is documented in `docs/design/threat-model.md`. In short:

- The Tang endpoints (`/adv`, `/rec`) are designed to be exposed to untrusted LAN clients.
- The setup/admin web UI runs over plain HTTP and is only meant to be reachable in setup mode or on a
  trusted LAN; see the documentation before enabling LAN admin access.
- Physical access to an unhardened board allows key extraction. Flash encryption, Secure Boot and NVS
  encryption profiles are provided for production deployments.

## Security-relevant design points

- Private keys never leave the device: not over HTTP, not over MQTT, not in logs.
- All network parsers are bounded and fuzzed; secrets are zeroized after use.
- A factory reset destroys keys irreversibly; existing Clevis bindings to the device will no longer unlock.
