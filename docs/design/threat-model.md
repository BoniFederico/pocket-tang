# Threat model

This document states what Pocket Tang protects, against whom, and what it does not protect. The
design notes reference it, and every security-relevant decision in the code and the ADRs points
back here.

## 1. What a Tang server protects

Network-Bound Disk Encryption (NBDE) binds a LUKS volume to the presence of a Tang server. The disk
key is never sent to the server. Clevis stores a JWE whose content-encryption key can only be
recomputed with the help of the server's private **exchange key** (McCallum-Relyea exchange; see
the design notes). Therefore:

- **Asset A1, the exchange private keys** (active and rotated): whoever holds A1 *and* a copy of
  the encrypted disk header can unlock the disk without the network. A1 is the crown jewel.
- **Asset A2, the signing private key**: it lets an attacker forge advertisements. A client that
  binds to a forged advertisement would encrypt to the attacker's exchange key, but only if the
  client does not pin the thumbprint (`thp`) or uses an `adv` file obtained from the attacker.
- **Asset A3, availability**: if Tang is unreachable, bound machines do not unlock automatically.
  They fall back to a passphrase prompt. Availability is a usability property, not a
  confidentiality one.
- **Asset A4, the configuration secrets**: the Wi-Fi password, the admin password hash and the
  setup access-point password.

A Tang server never sees disk keys, passphrases or plaintext. The `/rec` request contains only a
blinded point, and the answer is useless without the client's ephemeral private key. This is
why Tang may run over plain HTTP, as upstream tang does.

## 2. Trust boundaries and attackers

| # | Attacker | Capabilities | In scope |
|---|----------|--------------|----------|
| T1 | Remote LAN client | Sends arbitrary TCP/HTTP to the Tang port; reads all `/adv` | yes |
| T2 | LAN eavesdropper / active MITM | Sees and modifies plain HTTP on the LAN | yes |
| T3 | Wi-Fi neighbour during setup | Within radio range while setup mode runs | yes |
| T4 | Thief of a bound laptop/server | Has the encrypted disk, is *off* the LAN | yes (the goal of NBDE) |
| T5 | Thief of the Pocket Tang device | Physical possession, serial/JTAG access | partially (see §5) |
| T6 | Thief of *both* the disk and the device | Has everything | no: NBDE cannot help, use a passphrase or TPM+Tang (sss) |
| T7 | Malicious firmware update / supply chain | Replaces the firmware | only with Secure Boot (§5) |
| T8 | Side channels | Timing over the network, power analysis with physical access | network timing yes; power analysis no |

## 3. Threats and mitigations

### Network input (T1)

| Threat | Mitigation |
|--------|------------|
| Memory corruption through malformed HTTP/JSON/JWK | Every parser is bounded, non-recursive and fuzzed with libFuzzer in CI: HTTP head, JSON, base64url, JWK, key-store blob, form bodies, cookies, DNS. Host builds run under ASan/UBSan. Fixed-size buffers, no heap allocation in the request path. |
| Invalid-curve and small-subgroup attacks on `/rec` | The client point is checked for coordinate range and on-curve membership and must not be infinity (`pt_p521_point_check`). P-521 has cofactor 1. Private scalars are validated on load. |
| Key extraction via `/rec` | `/rec` returns `d·X` only for exchange keys. Requests carrying private key material are rejected (ADR-0003). Signing keys answer 403. |
| Timing leaks | Mbed TLS scalar multiplication uses constant-time algorithms with randomised projective coordinates (blinding). Secret comparisons use `pt_ct_memeq`. Kid lookup compares public thumbprints only. |
| Denial of service (slow clients, floods) | Event-driven server with per-request deadline, per-peer cap and eviction (ADR-0004). Bounded crypto queue (503 when full). Watchdogs. Verified on hardware under stress. |
| Abuse of `/rec` as an oracle | `/rec` reveals nothing beyond `d·X`, which is exactly the protocol's purpose. A lock switch can stop recoveries, and every recovery is counted and logged with the client IP. |

### LAN eavesdropping (T2)

- `/adv` and `/rec` over plain HTTP are safe by design (§1). Clients authenticate advertisements
  through the signing-key thumbprint (`thp`), which must be obtained out of band, for example from
  the admin page or the serial console.
- The admin page is **off on the LAN by default**. When enabled it runs over plain HTTP, so an
  active LAN attacker can capture the admin password and session. Recommendation: enable LAN admin
  only on a trusted network segment, and prefer the setup access point (WPA2-protected) for
  administration. HTTPS on the device was rejected for v1: a self-signed certificate on a device
  without a stable name gives users little real protection and costs about 40 KB of RAM. See the
  open issue for a TLS option.
- Session cookies are `HttpOnly; SameSite=Strict; Path=/admin`, every form carries a CSRF token,
  responses carry a strict CSP and `X-Frame-Options: DENY`, and login attempts are throttled
  exponentially.

### Setup mode (T3)

- Setup access point: WPA2-PSK with a random 12-character per-device password (about 60 bits,
  unambiguous alphabet). It is printed on the serial console at every boot, which requires
  physical access, and renewed by a factory reset.
- First-time setup (no admin password yet) is possible only on the setup access point.
- Setup mode is entered only by a physical button press or when unprovisioned, and it times out
  after 15 minutes of inactivity.
- The captive-portal DNS answers only on the access-point interface.

### Theft of a bound machine (T4)

This is the attack NBDE is designed for. The stolen machine cannot reach the Tang server and
therefore cannot unlock. Pocket Tang additionally offers the **lock** switch (persisted): flipping it
via the admin page (or Home Assistant, v1.1) makes every `/rec` fail, for example after you notice
a theft while the thief is still on your network.

### Physical access to the device (T5)

Without hardening, anyone holding the board can read the flash over USB in seconds and extract the
keys (A1). This is equivalent to stealing an upstream tang server's `/var/db/tang`. Mitigations:

1. **Flash encryption (release mode)** makes flash dumps useless.
2. **NVS encryption** protects keys and configuration inside NVS.
3. **Secure Boot** (v2 on ESP32 rev ≥ 3, C3, S3; v1 on older ESP32) prevents running modified
   firmware that would exfiltrate keys.
4. JTAG is disabled. ESP32-C3/S3 restrict the ROM download mode to Secure Download Mode.
   On the ESP32 the ROM download mode stays available but cannot read plaintext flash in release
   mode.

See the [hardening guide](../user/hardening.md). Residual risks with all of these enabled: fault
injection and side-channel attacks on the chip (published attacks exist against ESP32 rev < 3),
and an attacker who keeps the device *on your LAN* can still use it as a Tang server. Physical
security of the device matters, as with any Tang server.

### Software supply chain (T7)

- Pinned toolchain (ESP-IDF v5.5.6, Mbed TLS 3.6.7 verified by SHA-256), reproducible CI builds,
  SHA-256 checksums for release assets.
- Secure-profile images in CI are signed with throwaway keys and are never published.

## 4. Factory reset

A factory reset (BOOT ≥ 10 s or the admin page) destroys all keys. **Every Clevis binding to the
device stops working.** Machines then need their LUKS passphrase or another unlock method. This is
documented prominently in the README and the user guide, and the admin page requires typing
`RESET`.

## 5. Explicit non-goals

- Protection when an attacker has both the encrypted disk and the Tang device (T6). Use Shamir
  secret sharing (`sss`) across several Tang servers and/or a TPM.
- Protection against power analysis or fault injection on the chip.
- Confidentiality of the *fact* that a client unlocked (the server logs and counts recoveries).
