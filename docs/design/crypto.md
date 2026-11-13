# Cryptography details

This page documents the cryptographic layer: the `pt_crypto.h` interface, how each operation
maps onto Mbed TLS 3.6, which validations happen where, and the side-channel and hygiene measures
around them. The mathematics of the protocol is on the [McCallum-Relyea](mcallum-relyea.md) page.
Here the topic is the engineering.

## 1. The interface

All cryptography used by the portable core goes through `core/include/pt/pt_crypto.h`. The only
implementation is `core/crypto/mbedtls/pt_crypto_mbedtls.c`
([ADR-0001](../adr/0001-esp-idf-version-and-crypto-stack.md)). The interface follows four
conventions, stated in the header:

1. Scalars and coordinates are **fixed-width 66-byte big-endian** buffers, which is the JOSE
   encoding. There is no variable-length integer anywhere in the API.
2. Every function **validates its inputs and fails closed**.
3. **Secret intermediates are wiped** before returning.
4. Functions are reentrant if the registered RNG is. The platform nevertheless serialises all
   crypto work on one task ([Architecture](architecture.md)).

| Function | Purpose | Mbed TLS calls |
|----------|---------|----------------|
| `pt_crypto_set_rng`, `pt_crypto_random` | register and use the platform CSPRNG | none (adapter `mbed_rng` for `f_rng`) |
| `pt_hash` | SHA-1/224/256/384/512 over scatter/gather fragments | `mbedtls_sha1_*`, `mbedtls_sha256_*` (224 via `is224`), `mbedtls_sha512_*` (384 via `is384`) |
| `pt_p521_point_check` | $0 \le x,y < p$, on curve, not $\mathcal{O}$ | `mbedtls_ecp_point_read_binary`, `mbedtls_ecp_check_pubkey` |
| `pt_p521_scalar_check` | $1 \le d < n$ | `mbedtls_mpi_read_binary`, `mbedtls_ecp_check_privkey` |
| `pt_p521_keygen` | new key pair | `mbedtls_ecp_gen_keypair` |
| `pt_p521_public` | $dG$, to validate stored keys | `mbedtls_ecp_mul` with `grp.G` |
| `pt_p521_ecmr` | server step $Y = dX$ | `mbedtls_ecp_mul` |
| `pt_es512_sign` / `pt_es512_verify` | ECDSA P-521 / SHA-512, raw $r \,\|\, s$ | `mbedtls_ecdsa_sign_det_ext`, `mbedtls_ecdsa_verify` |
| `pt_pbkdf2_sha256` | admin password hashing | `mbedtls_pkcs5_pbkdf2_hmac_ext` |

The backend uses only **public** Mbed TLS APIs, with no access to `MBEDTLS_PRIVATE` fields. The
same file therefore compiles against upstream Mbed TLS 3.6.7 on the host and against ESP-IDF's
fork with hardware acceleration on the device. Compile-time guards refuse to build without
`MBEDTLS_ECP_DP_SECP521R1_ENABLED` or without SHA-1, SHA-256 and SHA-512. SHA-224 and SHA-384
degrade gracefully to `PT_ERR_UNSUPPORTED`, and the key store then simply never matches kids of
those lengths.

**Scatter/gather hashing.** `pt_hash` and `pt_es512_sign` take an array of `pt_iovec_t`
fragments. The JWS signing input `b64u(protected) || "." || b64u(payload)` is hashed from three
fragments in place, without being copied into a temporary buffer.

## 2. Encodings at the boundary

Mbed TLS reads and writes points in the SEC 1 uncompressed format `0x04 || X || Y` (133 bytes for
P-521). The helpers `point_read()` and `point_write()` convert between this and the 66 + 66 byte
`pt_p521_point_t`:

- `point_read()` builds `0x04 || x || y`, parses it, and immediately runs
  `mbedtls_ecp_check_pubkey()`. There is no code path that loads a point without validating it.
- `point_write()` refuses the point at infinity and checks that the output length is exactly 133
  bytes and starts with `0x04`.
- `scalar_read()` parses 66 bytes and immediately runs `mbedtls_ecp_check_privkey()`, which for
  short Weierstrass curves checks $1 \le d < n$.

## 3. Validation summary

| Where | What is validated | Code |
|-------|-------------------|------|
| `/rec` request point | canonical 66-byte base64url, range, on-curve, not $\mathcal{O}$ | `pt_jwk_parse` → `pt_p521_point_check`; again in `pt_p521_ecmr` |
| `/rec` result | not $\mathcal{O}$ | `point_write` |
| Every scalar used | $1 \le d < n$ | `scalar_read` in `ecmr`, `public`, `sign` |
| Stored keys at boot | blob checksum, then $dG = (x, y)$ for each key | `pt_keystore_load` |
| Imported private JWKs (host harness) | scalar range and $dG = (x, y)$ | `pt_jwk_parse(..., allow_private = true)` |
| Signature verification input | public point valid, $r, s$ parsed from fixed width | `pt_es512_verify` |

Why point validation is a security requirement and not just hygiene is explained in
[McCallum-Relyea §6](mcallum-relyea.md#6-point-validation-and-invalid-curve-attacks).

## 4. Scalar multiplication and blinding

`pt_p521_ecmr()` and `pt_p521_public()` call `mbedtls_ecp_mul(grp, R, m, P, f_rng, p_rng)`. Two
properties of Mbed TLS's implementation matter here.

**Regular, constant-time algorithm.** For short Weierstrass curves Mbed TLS uses a comb method
with constant-time table lookups. The sequence of field operations does not depend on the bits
of the secret scalar. This defends against timing attacks, which the
[threat model](threat-model.md) puts in scope for network timing (T8).

**Randomised projective coordinates.** Internally, points are kept in Jacobian coordinates, where
$(X : Y : Z)$ represents the affine point $(X/Z^2,\ Y/Z^3)$. For any non-zero $\lambda \in
\mathbb{F}_p$,

$$
(X : Y : Z) \;\sim\; (\lambda^2 X : \lambda^3 Y : \lambda Z),
$$

so the same point has $p - 1$ different representations. Mbed TLS picks a random $\lambda$ for
the input point (Coron's countermeasure [3]). The intermediate values processed by the CPU are
then unpredictable even for a known input, which hampers differential side-channel analysis. The
result is unaffected. `test_ecmr_matches_upstream` checks this: two different RNG streams give
the byte-identical upstream reply.

**The RNG is mandatory.** In Mbed TLS 3.x the blinding needs `f_rng`. `pt_p521_ecmr()`,
`pt_p521_public()` and `pt_p521_keygen()` return `PT_ERR_STATE` if no RNG is registered, instead
of falling back to an unblinded computation. `test_requires_rng` covers this.

!!! warning "What this does not cover"
    Blinding and constant-time algorithms are countermeasures against *timing* and simple
    *power* observations. The threat model explicitly excludes power analysis and fault
    injection by an attacker with physical access to the chip (§5 of the
    [threat model](threat-model.md)). Physical protection relies on flash and NVS encryption
    instead.

## 5. Deterministic ECDSA

`pt_es512_sign()` uses `mbedtls_ecdsa_sign_det_ext()` (RFC 6979) when `MBEDTLS_ECDSA_DETERMINISTIC`
is defined. The firmware enables it with `CONFIG_MBEDTLS_ECDSA_DETERMINISTIC=y` in
`sdkconfig.defaults`. For the host build, the unit test `test_sign_verify_and_determinism`
asserts that two signatures of the same message are identical, so a non-deterministic host
configuration would fail CI. The nonce $k$ is derived with an HMAC-based deterministic generator
from the private key and the message hash. The RNG is still passed in and used only for
blinding.

**Why deterministic nonces?** ECDSA is extremely fragile with respect to $k$. If two signatures
$(r, s_1)$ and $(r, s_2)$ on hashes $h_1 \neq h_2$ reuse the same $k$, then

$$
k = \frac{h_1 - h_2}{s_1 - s_2} \bmod n, \qquad d = \frac{s_1 k - h_1}{r} \bmod n,
$$

and the private key is recovered with two lines of algebra. Biased (not just repeated) nonces
also leak the key through lattice attacks. RFC 6979 removes the dependency on RNG quality at
signing time. A second benefit, used by the advertisement cache, is **reproducibility**: the same
key and payload always give the same signature (`test_sign_verify_and_determinism`).

If a build lacked `MBEDTLS_ECDSA_DETERMINISTIC`, the code would fall back to randomised
`mbedtls_ecdsa_sign()`. The advertisement cache would still be correct, but it would no longer
be byte-stable across rebuilds.

## 6. Hashes and thumbprints

Thumbprints use all five SHA variants (see [JOSE §6](jose.md#6-jwk-thumbprints-rfc-7638)), ES512
uses SHA-512, and the key-store checksum and PBKDF2 use SHA-256. The generated firmware
configuration (`firmware/sdkconfig`) has `CONFIG_MBEDTLS_HARDWARE_SHA=y`, so ESP-IDF may route SHA
computations to the SHA accelerator. No separate measurement of its effect exists in
[measurements](../measurements.md).

## 7. Password hashing

Admin passwords are hashed with PBKDF2-HMAC-SHA256 (RFC 8018) with a 16-byte salt from the CSPRNG,
10 000 iterations and a 32-byte output (`pt_pw_set`). The salt, hash and iteration count are
stored in NVS, so the iteration count can be raised later without invalidating existing
passwords. Verification recomputes the hash and compares it with `pt_ct_memeq`. A memory-hard
function such as Argon2 would be stronger against GPU attackers, but it is not available in
Mbed TLS 3.6, and its memory cost competes with the device's ~150 KB of free heap. The login
back-off ([Implementation §9](implementation.md#9-admin-ui-security)) limits online guessing.

## 8. Zeroisation

Secrets are wiped with `pt_zeroize()`, a byte loop through a `volatile` pointer that the compiler
may not remove as a dead store.

| Secret | Wiped where |
|--------|-------------|
| Mbed TLS scalars (`mbedtls_mpi`) | `mbedtls_mpi_free()` zeroises the limbs before freeing |
| SHA-512 digest in signing | end of `pt_es512_sign` |
| Generated scalar on keygen failure | `pt_p521_keygen` |
| Parsed JWK with `d` | `pt_jwk_wipe`, including on every parse error after `d` was decoded |
| Key slots | on generation failure, on purge (`remove_at`), on load failure (`pt_keystore_wipe`) |
| Key-store blob buffers | after `pt_keystore_load` in `main.c` and after saving in `pt_engine_persist_keys` |
| `/rec` result point | after it has been serialised (`serve_rec`) |
| HTTP connection buffers | on every close (`conn_close`), because they may contain request bodies |
| Passwords and config copies in the UI | after use (`do_setup`, `do_login`, console commands) |
| Wi-Fi config structs | after `esp_wifi_set_config` |
| Session tokens | `pt_session_end` |

The engine's key store must, of course, stay in RAM for the lifetime of the firmware. Protecting
RAM against an attacker with a debugger is out of scope; JTAG is disabled on hardened devices.

## 9. Constant-time comparisons

`pt_ct_memeq()` ORs together the XOR of all byte pairs and examines the result once, so its
running time depends only on the length. It is used wherever one operand is secret, or where an
early exit would reveal how much of an attacker's guess was right:

- key-store checksum and the $dG = (x, y)$ check on load and on import;
- PBKDF2 password hash, session cookie token and CSRF token;
- duplicate detection on key import.

It is deliberately **not** used for `kid` lookup. Thumbprints are public, derived from public
keys and published in `/adv`, so a timing difference reveals nothing.

## 10. Hardware MPI acceleration

The ESP32 has an RSA/big-number accelerator. With `CONFIG_MBEDTLS_HARDWARE_MPI=y` (the default in
`sdkconfig.defaults`), ESP-IDF's Mbed TLS port routes multi-precision multiplication to it, while
the rest of the arithmetic stays in software. The effect on `/rec` was measured with the
`bench-swmpi` profile, which disables the accelerator ([measurements](../measurements.md)):

| Big-number arithmetic | `/rec` crypto time (mean) | max |
|-----------------------|---------------------------|-----|
| Hardware MPI (default) | 531–546 ms | 565 ms |
| Software MPI | 771 ms | 780 ms |

The speed-up is 1.45×. [Performance](performance.md#4-effect-of-hardware-mpi) uses Amdahl's
law to estimate how much of the software time the accelerated part represents. No source change
is needed to switch: the backend calls the same public API either way.

## 11. Random number generation

| Context | Source | Notes |
|---------|--------|-------|
| Device, all crypto | `esp_fill_random()` via `pt_crypto_set_rng(esp_rng, NULL)` in `pt_worker_start()` | The hardware RNG is a true RNG while Wi-Fi is running, so keys are generated only after Wi-Fi has started ([Implementation §7](implementation.md#7-keys-are-generated-after-wi-fi-has-started)). |
| Device, setup-AP password | `esp_random()` between `bootloader_random_enable()` and `bootloader_random_disable()` | Generated before Wi-Fi starts, so the SAR ADC entropy source is enabled explicitly. |
| Host harness | `getrandom()` | `host/tangd_host.c` |
| Fuzzers | fixed-seed linear congruential generator | Deterministic, for reproducible fuzzing. **Never** used outside `core/fuzz/`. |
| Unit tests | test RNG with selectable seed (`tu_use_test_rng`) | Used to show that blinding randomness does not change results. |

Consumers of the RNG are key generation, the blinding in every scalar multiplication and
signature, PBKDF2 salts, session tokens and CSRF tokens. If the registered RNG reports failure,
`pt_crypto_random()` returns `PT_ERR_CRYPTO`, and the adapter passes
`MBEDTLS_ERR_ECP_RANDOM_FAILED` to Mbed TLS, which aborts the operation.

## 12. Known limitations

- **Group setup per call.** Each operation calls `mbedtls_ecp_group_load()` and frees the group
  afterwards. This keeps the functions stateless and reentrant, at the cost of re-initialising
  the curve constants each time. Its share of the `/rec` time has not been measured.
- **Heap use inside Mbed TLS.** See [Implementation §3](implementation.md#3-fixed-buffers-no-heap-in-the-request-path).
- **Mbed TLS 4 migration.** The public ECP API used here is gone in Mbed TLS 4.0 (ADR-0001,
  issue #17).

## References

1. Mbed TLS 3.6, API headers `ecp.h`, `ecdsa.h`, `bignum.h`, `pkcs5.h`.
   <https://github.com/Mbed-TLS/mbedtls/tree/mbedtls-3.6.7>
2. Mbed TLS, *Migrating from Mbed TLS 2.x to Mbed TLS 3.0* (RNG now required).
   <https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.7/docs/3.0-migration-guide.md>
3. J.-S. Coron, "Resistance against Differential Power Analysis for Elliptic Curve
   Cryptosystems", CHES 1999, LNCS 1717.
4. RFC 6979, *Deterministic Usage of DSA and ECDSA*. <https://www.rfc-editor.org/rfc/rfc6979>
5. RFC 7518, §3.4 (ES512). <https://www.rfc-editor.org/rfc/rfc7518>
6. RFC 8018, *PKCS #5 v2.1* (PBKDF2). <https://www.rfc-editor.org/rfc/rfc8018>
7. SECG, *SEC 1: Elliptic Curve Cryptography*, v2.0, §2.3.3 (point encoding).
   <https://www.secg.org/sec1-v2.pdf>
8. Espressif, *ESP-IDF Programming Guide: Random Number Generation*.
   <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html>
9. D. Hankerson, A. Menezes, S. Vanstone, *Guide to Elliptic Curve Cryptography*, Springer, 2004
   (Jacobian coordinates, comb methods).
