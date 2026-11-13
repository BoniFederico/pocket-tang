# Implementation choices

This page goes through the important implementation decisions. For each one it states the
decision, the alternatives that were considered, and the reasoning. Four of the decisions have
formal ADRs, which are linked. The others are documented here from the code. The recurring
themes are **bounded resources**, **fail closed** and **byte-exact compatibility with
upstream**.

## 1. Toolchain: ESP-IDF v5.5.6 with Mbed TLS 3.6.7

**Decision** ([ADR-0001](../adr/0001-esp-idf-version-and-crypto-stack.md)): use ESP-IDF v5.5.6
and its Mbed TLS 3.6, not the newer ESP-IDF v6.0 line.

**Why.** ESP-IDF 6.0 ships Mbed TLS 4.0. Its migration guide states that `bignum.h`, `ecp.h`,
`ecdh.h` and `ecdsa.h` are no longer public, and that applications must use PSA Crypto instead.
`/rec` must return the full point $sX$ ([McCallum-Relyea §2.3](mcallum-relyea.md#23-why-the-server-must-return-the-full-point)),
but PSA's raw key agreement returns only the $x$-coordinate, and PSA has no "multiply an
arbitrary point" primitive.

**Alternatives.** (2) ESP-IDF 6 plus a vendored constant-time P-521 implementation: new
security-critical arithmetic to validate, no hardware MPI, two crypto code bases. (3) ESP-IDF 6
with Mbed TLS private headers: explicitly discouraged upstream and liable to break on any patch
release.

**Consequences.** The Mbed TLS dependency is confined to one file behind `pt_crypto.h`. The host
build fetches exactly Mbed TLS 3.6.7 and verifies it by SHA-256 (`core/CMakeLists.txt`), so the
unit tests run against the same library version as the firmware. ESP-IDF v5.5 is supported for
30 months from its initial release, which per ADR-0001 means until roughly early 2028. Issue #17
tracks the path to v6.

## 2. Own strict JSON parser

**Decision** ([ADR-0002](../adr/0002-own-json-parser.md)): a purpose-built tokenizer and writer
(`core/src/pt_json.c`) instead of cJSON or jsmn.

**Design.**

- Iterative state machine (`enum state` with seven states). Nesting is tracked in fixed arrays
  of depth `PT_JSON_MAX_DEPTH` = 8 instead of on the C stack, so stack use does not depend on
  the input.
- The token array lives in caller memory. `/rec` uses 48 tokens on the stack
  (`REC_TOKENS`), and running out of tokens is an error, not a reallocation.
- Strict RFC 8259 grammar: no comments, no trailing commas, strict numbers (tokenised, never
  evaluated), valid UTF-8, no raw control characters.
- Member lookup returns a distinct error for **duplicate keys**. A JWK with two `x` members is
  rejected instead of being silently resolved to the first or the last one.
- The writer always emits object members in lexicographic order, so RFC 7638 thumbprint input
  comes out canonical without a sorting step. It latches the first error (overflow, unbalanced
  nesting), so callers check once at `pt_jw_finish()`.

**Alternatives.** cJSON allocates a heap tree, parses recursively, is permissive in places, and
is an ESP-IDF component, so the host build would need a separate copy. jsmn is small but not
strict by default, decodes no escapes, has no writer, and would still need a validation layer.

**Why.** The only JSON a Tang server must understand is a small JWK. A parser of about 500
lines can be reviewed line by line and fuzzed (`fuzz_json`, `fuzz_jwk`), and it gives full
control over limits and failure modes.

## 3. Fixed buffers, no heap in the request path

**Decision.** All request-path memory is static or on the stack, with capacities fixed at
compile time. The following capacities are declared in the source (they are constants, not
measurements):

| Buffer | Capacity | Where |
|--------|----------|-------|
| Connection buffer, per slot | `PT_HTTP_MAX_HEAD` + `PT_SRV_MAX_BODY` = 2048 + 2048 bytes | `pt_srv_conn_t`, 6 slots (`PT_SRV_MAX_CONNS`) |
| Tang response | `PT_TANG_RESP_MAX` = 4096 bytes | `s_out` in `pt_httpd.c` |
| Advertisement payload cache | `PT_TANG_ADV_PAYLOAD_MAX` = 1600 base64url chars | `pt_tang_t` |
| Cached signatures | 8 × 132 bytes | `pt_tang_t.sig` |
| Admin page / extra headers | 7168 / 768 bytes | `s_page`, `s_hdrs` in `ui.c` |
| Key-store blob | `PT_KEYSTORE_BLOB_MAX` = 1640 bytes | static buffers in `main.c` and `pt_worker.c` |
| DNS query / reply | 512 / 512 bytes | `pt_dnsd.c` |

Limits follow from these capacities: request bodies over 2048 bytes get 413, heads over 2048
bytes get 431, and request targets over 512 bytes get 414 (`pt_http.h`).

**Why.** On a device with about 150 KB of free heap, fragmentation and allocation failure under
load are real risks, and they are hard to test. With static buffers, the worst case is known at
link time. The measured result is a heap that does not move under stress: 146.7 KB free after
boot and 146.6 KB after 120 s + 180 s of stress ([measurements](../measurements.md)).

!!! note "The exception: Mbed TLS bignums"
    The core does not allocate, but Mbed TLS's multi-precision integers (`mbedtls_mpi`)
    allocate their limbs on the heap internally during every scalar multiplication. They are
    freed before `pt_p521_ecmr()` returns. The heap measurement under stress is the empirical
    check that this does not leak or fragment. The lowest free heap ever observed, 106.7 KB, was
    dominated by lwIP buffers under heavy stress.

## 4. Crypto worker, bounded queue and 503

**Decision.** One FreeRTOS task (`pt_worker`) owns the engine and the key material. Other tasks
submit jobs through `pt_worker_run()`, which never waits for queue space. A full queue returns
immediately and becomes HTTP 503 (counted as `busy` in the statistics).

**Alternatives.** (a) A mutex around the engine: every caller would need a large enough stack
for Mbed TLS ECP operations, and a burst of callers would queue without bound on the mutex.
(b) Performing crypto directly on the HTTP task: workable with a single HTTP task, but the admin
UI, the test console and the planned MQTT integration also touch keys.

**Why.**

- *Single owner.* Key material is only ever touched on one task, so there are no data races by
  construction and no locks to get wrong.
- *Dedicated stack.* Only the worker needs the 8 KB stack for ECP arithmetic. The HTTP task gets
  6 KB. Measured high-water marks: 4364 bytes free of 8192 on the worker, and 3536 bytes free of
  6144 on the HTTP task.
- *Back-pressure instead of memory growth.* A request that cannot be served promptly is refused
  with a cheap 503 rather than piling up.

With the current design the HTTP server is a single task and waits synchronously for each job,
so HTTP traffic alone keeps at most one job in the queue. The bound of 4 protects against the
other producers (test console, boot code, future MQTT), and it keeps the invariant explicit if
the server ever gains more tasks.

## 5. Advertisement cache with per-key deterministic signatures

**Decision.** `pt_tang_refresh()` builds the advertisement payload and signs it **once per ES512
key**, active and rotated, whenever the key store's `generation` counter changes. `/adv` and
`/adv/{kid}` then only concatenate cached strings (`serve_adv()`).

**Why.**

- *Cost.* An ES512 signature needs a scalar multiplication $kG$, the same order of work as
  `/rec`. Signing per request would make `/adv` as slow as `/rec` and turn it into a cheap
  denial-of-service lever. With the cache, `/adv` p50 is 26 ms against 573 ms for `/rec`.
- *Rotated signers.* `/adv/{kid}` must be signed by a rotated signing key when a client asks for
  it. Caching a signature per key covers this without any work at request time.
- *Determinism.* Signatures use RFC 6979 nonces, so rebuilding the cache, for example after a
  reboot, yields byte-identical signatures for the same keys and payload. The refresh is
  idempotent, and responses are stable across restarts.

**Invalidation.** Every key-store mutation (rotate, import, purge) increments `generation`.
`pt_tang_refresh()` is called after every change and lazily on `/adv`. If the refresh fails, the
cache is marked invalid and `/adv` answers 500 rather than serving stale data.

## 6. Key-store persistence format

**Decision.** The key store is serialised to a versioned binary blob by `pt_keystore_save()` and
stored as one NVS blob (`ptkeys/ks`).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic `"PTKS"` |
| 4 | 1 | version = 1 |
| 5 | 1 | key count $N \le 8$ |
| 6 | 2 | reserved, must be zero |
| 8 + 200 $i$ | 1 | `alg`: 1 = ES512, 2 = ECMR |
| 9 + 200 $i$ | 1 | flags: bit 0 = rotated, other bits must be zero |
| 10 + 200 $i$ | 66 | private scalar $d$ |
| 76 + 200 $i$ | 66 | public $x$ |
| 142 + 200 $i$ | 66 | public $y$ |
| 8 + 200 $N$ | 32 | SHA-256 over all preceding bytes |

The total length is $8 + 200N + 32$ bytes: 440 bytes for the initial pair, 1640 bytes at most.

**Loading is fail-closed** (`pt_keystore_load()`):

1. Exact length for the declared count, magic, version and reserved bytes are checked.
2. The SHA-256 trailer is compared in constant time.
3. Each key's `alg` and flags are checked.
4. $d G$ is recomputed and compared with the stored $(x, y)$. This single check proves that the
   scalar is in range and that the point is valid.
5. At most one active key per algorithm is allowed.

Any failure wipes the partially loaded store and returns an error. The firmware then **halts
with the error LED** instead of generating fresh keys (`load_keys_job()` in `main.c`). Silently
replacing keys would break every Clevis binding with no indication of why.

!!! warning "The checksum is not a MAC"
    SHA-256 detects corruption, such as a torn write or flash wear. It does not authenticate the
    blob: anyone who can write the flash can recompute it. Confidentiality and integrity against
    an attacker with physical access come from NVS encryption and flash encryption on hardened
    devices ([hardening guide](../user/hardening.md)). The `nvs_key` partition is marked
    `encrypted` in `partitions.csv` for this purpose.

The load-time validation is not free: about 0.5 s per stored key, measured as part of the boot
time ([measurements](../measurements.md)). It is paid once per boot.

**Rotation semantics** follow upstream. `pt_keystore_rotate()` generates a new ES512 + ECMR pair
and marks *all* existing keys rotated. Rotated keys are not advertised but remain valid for
`/rec` and as signers for `/adv/{kid}`. With 8 slots, the active pair plus three rotated
generations fit. Further rotations fail with `PT_ERR_LIMIT` until the administrator purges
rotated keys, which breaks bindings to them and is therefore an explicit action.

## 7. Keys are generated after Wi-Fi has started

**Decision.** `start_keys()` runs after `pt_wifi_start_sta()` or `pt_wifi_start_setup()` in both
modes.

**Why.** The ESP32 RNG produces true random numbers only while an entropy source is active: the
RF subsystem (Wi-Fi or Bluetooth) or the SAR ADC enabled with `bootloader_random_enable()`.
Without one, the output is only pseudo-random. A P-521 private key generated from a weak RNG is
a catastrophic, silent failure. Ordering the boot sequence avoids it by construction. The one
secret generated *before* Wi-Fi, the setup-AP password, explicitly brackets its generation with
`bootloader_random_enable()` / `bootloader_random_disable()` (`pt_store_setup_password()`).

## 8. Own HTTP server instead of `esp_http_server`

**Decision** ([ADR-0004](../adr/0004-own-http-server.md)): replace ESP-IDF's `esp_http_server`
with `core/net/pt_server.c`.

**Finding.** Hardware-in-the-loop stress testing showed that a single *slowloris* client, which
sends one header byte per second, stalled the whole server. `esp_http_server` reads request
heads with blocking `recv()` on its only task. In 120 s, 12 requests succeeded and 49 client
connections failed.

**Design of `pt_server`.**

- Non-blocking sockets multiplexed with `select()`. No read ever blocks on one client.
- A **total deadline per request** (5000 ms on the device): head plus body must arrive within
  it, otherwise 408. This counters slow senders. A per-read timeout would not, because the
  attacker could reset it with every byte.
- **Bounded connections** (`CONFIG_PT_HTTPD_MAX_SOCKETS`, default 5, out of 6 static slots) with
  a **per-peer cap** of `max_conns − 2`. When the table is full, the **oldest** connection is
  evicted. Every open connection is incomplete by construction, because complete requests are
  answered and closed immediately.
- One request per connection (`Connection: close`). There is no keep-alive and no chunked
  encoding, which Tang clients do not need. `Transfer-Encoding` gets 501.
- Head parsing by the fuzzed `pt_http` parser. Connection buffers are zeroised on close because
  they may contain request bodies.

**Result** ([measurements](../measurements.md)): under the same stress test, 415 `200` responses
plus 211 correct 4xx and zero client-side connection errors, against 12 and 49 before. `/adv`
p50 dropped from 92 ms to 26 ms and `/rec` p50 from 622 ms to 573 ms. The price is 24 KB of
static connection buffers. The server is also used unchanged by `tangd-host` on Linux, where
`test_server.c` runs slowloris, flood and eviction scenarios under ASan/UBSan.

## 9. Admin UI security

The admin UI (`firmware/main/ui.c`, with portable helpers in `core/src/pt_web.c`) can change Wi-Fi
settings, rotate or purge keys, toggle the recovery lock and factory-reset the device. It is
therefore protected in depth:

| Measure | Implementation |
|---------|----------------|
| Exposure | Always on the setup AP. On the LAN only if "LAN admin" is enabled (off by default), and never without an admin password (404). First-time setup only on the AP. |
| Password storage | PBKDF2-HMAC-SHA256, 10 000 iterations (`PT_PW_ITER_DEFAULT`), 16-byte random salt, 32-byte hash. Verified with a constant-time comparison. Policy: 8–64 bytes, no control characters. |
| Login throttling | Global back-off, not per client. From the third consecutive failure, logins are blocked for 5 s, doubling up to 300 s (HTTP 429). Reset on success. Being global, it also lets a LAN attacker delay the administrator's own login, which is accepted as a nuisance rather than a security risk. |
| Session | One session at a time. 16-byte random token in cookie `ptsid` with `Path=/admin; HttpOnly; SameSite=Strict` and no `Max-Age` (a browser-session cookie). The server-side expiry, 10 minutes of inactivity, slides on every authorised action, so the server alone decides when a session ends. Constant-time token check, and the cookie must appear exactly once. No `Secure` flag, because the UI is served over plain HTTP. |
| CSRF | A separate 16-byte random token in a hidden field of every form. Every state-changing POST requires session **and** token. |
| Output encoding | All dynamic text is HTML-escaped (`pt_html_escape`). |
| Headers | `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. |
| No JavaScript | Server-rendered pages only. The CSP forbids scripts entirely. |
| Dangerous actions | Factory reset requires typing `RESET`. Private keys are never displayed or exported. |
| DNS rebinding | On the AP, `/admin` is served only if the `Host` header names the device (AP address, `<hostname>.local` or the local address). Anything else is redirected. |

**Why no HTTPS?** The [threat model](threat-model.md) records the trade-off. A self-signed
certificate on a device without a stable name gives users little real protection and costs RAM,
so LAN admin is off by default and the WPA2-protected setup AP is the recommended way to
administer the device. Issue #16 tracks a TLS option.

## 10. Setup access point

- **SSID** `PocketTang-XXXX`, derived from the last two bytes of the soft-AP MAC.
- **WPA2-PSK** with CCMP, at most 2 stations, channel 6.
- **Password**: 12 characters from a 32-symbol alphabet without look-alikes (`0 O 1 l I`
  removed). That is $12 \times \log_2 32 = 60$ bits. Each character uses 5 random bits
  (`esp_random() & 31`), so there is no modulo bias. It is generated once per device and renewed
  by a factory reset. It is printed on the serial console at every boot, which requires physical
  access.
- **AP+STA** when the device is provisioned, so Tang keeps serving on the LAN during setup.
- **Captive portal**: `pt_dnsd` binds UDP 53 to the AP address only and answers every A query
  with `192.168.4.1`. AAAA queries get an empty answer so that clients fall back to IPv4. Any
  HTTP request on the AP redirects to `/admin`.
- **Timeout**: 15 minutes without configuration changes and without connected stations
  (`CONFIG_PT_SETUP_TIMEOUT_MIN`), only when provisioned.

## 11. Button and LED

The BOOT button (GPIO0 on the reference board, active low) is polled every 20 ms by its own task.
GPIO0 is also a boot-strapping pin, so only presses at runtime are detected.

| Hold time | LED while holding | Action on release |
|-----------|-------------------|-------------------|
| < 3 s | unchanged | none (pattern restored) |
| 3 – 10 s | very fast blink (10 Hz) from 3 s | restart into setup mode, keys kept |
| ≥ 10 s | solid on from 10 s | factory reset: keys and settings erased, restart |

Acting **on release**, with the LED changing at each threshold, lets the user see which action
will happen before committing to it. The 10 s threshold makes an accidental factory reset, which
breaks every binding, unlikely. Every LED state change is logged as `PT_LED <name>`, and button
events as `PT_BUTTON ...`, so the hardware-in-the-loop runner can verify the logic without a
camera.

## 12. Deliberate deviations from upstream

[ADR-0003](../adr/0003-deviations-from-upstream-tang.md) lists the only intentional differences
from `tangd` 14. Everything else, including status codes, content types, odd routes like
`//adv//`, query strings giving 404 and `HEAD` giving 405, JWS serialisation and `/rec` reply
bytes, matches upstream and is checked in CI.

| Request | upstream | Pocket Tang | Rationale |
|---------|----------|-------------|-----------|
| `/rec` JWK containing a valid private `d` | 200 (ignored) | 400 | Requests never need private material. Refusing keeps scalar handling off the request path. |
| `/rec` body over 2048 bytes | 413 at a larger limit | 413 at 2048 bytes | A clevis request is about 230 bytes. A small bound protects the device. |
| `GET /version` | 404 (tang 14) | 200 with name and version | Diagnostics. Later upstream releases added it too. |
| `/rec` while the lock switch is on | n/a | 403 | Pocket Tang feature (kill switch). |

`tang_pub` is included in `/rec` replies by default, as in tang 15 and later. It can be disabled
(`include_tang_pub`), and the byte-exact fixture test runs with it disabled.

## 13. Smaller choices worth knowing

- **Thumbprints are cached** for all five hashes per key, so `kid` lookup costs one base64url
  decode and at most eight `memcmp`s. There is no hashing at request time.
- **Kid length bound**: kids longer than 86 characters (the S512 length) can never match. They
  are reported as not found without further work.
- **Defensive double check**: the request point is validated in `pt_jwk_parse()` and again in
  `pt_p521_ecmr()`. The second check is redundant on the `/rec` path but keeps
  `pt_p521_ecmr()` safe for any future caller. An on-curve check costs a few field
  multiplications, negligible next to the scalar multiplication.
- **Watchdogs**: the task watchdog is enabled with a 10 s timeout (`sdkconfig.defaults`), well
  above the longest legitimate job.
- **Compiler hardening** on the device: `-Os`, strong stack protector (`STACK_CHECK_MODE_STRONG`),
  and in the test profile all functions are stack-checked, with light heap poisoning and an
  end-of-stack watchpoint.

## References

1. Pocket Tang ADRs [0001](../adr/0001-esp-idf-version-and-crypto-stack.md),
   [0002](../adr/0002-own-json-parser.md), [0003](../adr/0003-deviations-from-upstream-tang.md),
   [0004](../adr/0004-own-http-server.md).
2. RFC 8259, *JSON*. <https://www.rfc-editor.org/rfc/rfc8259>
3. RFC 8018, *PKCS #5 v2.1* (PBKDF2). <https://www.rfc-editor.org/rfc/rfc8018>
4. RFC 6265, *HTTP State Management Mechanism* (cookies). <https://www.rfc-editor.org/rfc/rfc6265>
5. W3C, *Content Security Policy Level 3*. <https://www.w3.org/TR/CSP3/>
6. OWASP, *Cross-Site Request Forgery Prevention Cheat Sheet*.
   <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
7. RFC 6979, *Deterministic Usage of DSA and ECDSA*. <https://www.rfc-editor.org/rfc/rfc6979>
8. Espressif, *ESP-IDF Programming Guide: Random Number Generation*.
   <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html>
9. Espressif, *ESP-IDF Programming Guide: NVS Encryption, Flash Encryption*.
   <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/>
