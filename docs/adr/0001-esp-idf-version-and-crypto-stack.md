# ADR-0001: ESP-IDF v5.5 with Mbed TLS 3.6 as the crypto stack

- Status: Accepted
- Date: 2026-11-13
- Issue: #1

## Context

The project brief asks for the latest stable ESP-IDF release and Mbed TLS as shipped with it. On the
decision date the latest stable line is **ESP-IDF v6.0.x** (v6.0.3), which ships **Mbed TLS 4.0** built on
TF-PSA-Crypto 1.0. The Mbed TLS 4.0 / TF-PSA-Crypto 1.0 migration guides state that the headers
`mbedtls/bignum.h`, `mbedtls/ecp.h`, `mbedtls/ecdh.h` and `mbedtls/ecdsa.h` "and their former content are no
longer available", and that applications must use the PSA Crypto API instead.

The Tang recovery step (McCallum-Relyea exchange) requires the server to compute `Y = s·X` for an
arbitrary client point `X` and return the **full point** `(x, y)`; the client then computes `Y − e·S`.
PSA key agreement (`psa_raw_key_agreement` with `PSA_ALG_ECDH`) returns only the x-coordinate of the shared
point, which is insufficient: the client cannot disambiguate the sign of `y` and upstream `jose`/`clevis` do
not attempt to. There is no PSA primitive for raw scalar multiplication returning a point.

The previous line, **ESP-IDF v5.5.x** (v5.5.6 at the decision date), ships Mbed TLS 3.6 (an upstream LTS
branch) with the public `mbedtls_ecp_*`/`mbedtls_mpi_*` APIs and ESP hardware MPI hooks. Per Espressif's
support policy each minor release receives 30 months of support from its initial release, so v5.5 remains in
maintenance (bug-fix) support until roughly early 2028.

## Options considered

1. **ESP-IDF v5.5.6 + Mbed TLS 3.6 (public ECP API).** Mature, constant-time `mbedtls_ecp_mul` with
   randomised projective coordinates, hardware MPI acceleration available, same library on host and target.
   Cost: not the newest IDF line; a future port to v6 must solve the ECP gap.
2. **ESP-IDF v6.0.3 + a vendored constant-time P-521 implementation** (e.g. BearSSL `i31` or own code) for
   ECMR, with ES512/SHA through PSA. Cost: new security-critical arithmetic to validate, no hardware MPI
   benefit, two crypto code bases on the device.
3. **ESP-IDF v6.0.3 using Mbed TLS private headers** (`mbedtls/private/ecp.h`,
   `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS`). Explicitly discouraged by upstream; may break on any patch release.

## Decision

Option 1: **ESP-IDF v5.5.6 with Mbed TLS 3.6**.

All crypto used by the portable core goes through a small backend interface (`core/include/pt/pt_crypto.h`)
so that the Mbed TLS dependency is confined to `core/crypto/mbedtls/`. The host build pins the same Mbed TLS
3.6 version as the ESP-IDF submodule.

## Consequences

- CI pins `esp_idf_version: v5.5.6`; Dependabot does not track IDF, so a maintainer bumps the pin for
  v5.5.x patch releases.
- A tracking issue documents the path to ESP-IDF v6 (options 2/3 above, or a future PSA extension).
- Secure Boot v2, flash encryption and NVS encryption are all available in v5.5.
