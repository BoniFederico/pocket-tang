/**
 * @file pt_crypto.h
 * @brief Cryptographic backend interface used by the portable core.
 *
 * The core never touches a crypto library directly; everything goes through this interface so
 * that the backend (Mbed TLS 3.6 today, see ADR-0001) can be replaced without touching protocol
 * code. Only P-521 is supported, which is what upstream Tang generates by default.
 *
 * Conventions:
 *  - Scalars and coordinates are fixed-width 66-byte big-endian buffers (JOSE encoding).
 *  - Every function validates its inputs and fails closed.
 *  - Secret intermediate values are wiped before returning.
 *  - Functions are reentrant as long as the registered RNG is; the platform layer nevertheless
 *    serialises all crypto work on one worker task (see the design notes).
 */
#ifndef PT_CRYPTO_H
#define PT_CRYPTO_H

#include "pt/pt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Hash algorithms used for JWK thumbprints (tang accepts all five) and ES512. */
typedef enum pt_hash_alg {
    PT_HASH_SHA1 = 0,   /**< "S1" */
    PT_HASH_SHA224 = 1, /**< "S224" */
    PT_HASH_SHA256 = 2, /**< "S256" (default thumbprint hash) */
    PT_HASH_SHA384 = 3, /**< "S384" */
    PT_HASH_SHA512 = 4, /**< "S512" */
    PT_HASH_COUNT = 5
} pt_hash_alg_t;

/** Largest digest size in bytes. */
#define PT_HASH_MAX_LEN 64

/** A scatter/gather input fragment. */
typedef struct pt_iovec {
    const void *ptr;
    size_t len;
} pt_iovec_t;

/** An affine P-521 point with fixed-width big-endian coordinates. */
typedef struct pt_p521_point {
    uint8_t x[PT_P521_LEN];
    uint8_t y[PT_P521_LEN];
} pt_p521_point_t;

/**
 * @brief Random number source. Must fill @p buf with @p len bytes from a CSPRNG.
 * @return 0 on success, non-zero on failure.
 */
typedef int (*pt_rng_fn)(void *ctx, uint8_t *buf, size_t len);

/**
 * @brief Register the platform CSPRNG. Must be called before any key generation or signing.
 *        Without an RNG those operations return PT_ERR_STATE (fail closed).
 */
void pt_crypto_set_rng(pt_rng_fn fn, void *ctx);

/**
 * @brief Fill @p buf with random bytes from the registered RNG.
 * @return PT_OK, PT_ERR_STATE if no RNG is registered, PT_ERR_CRYPTO if it failed.
 */
pt_err_t pt_crypto_random(uint8_t *buf, size_t len);

/** @brief Digest length in bytes of @p alg, or 0 for an invalid value. */
size_t pt_hash_len(pt_hash_alg_t alg);

/**
 * @brief Hash the concatenation of @p n fragments.
 * @param out Receives pt_hash_len(alg) bytes.
 * @return PT_OK, PT_ERR_UNSUPPORTED if the backend lacks the algorithm, PT_ERR_CRYPTO.
 */
pt_err_t pt_hash(pt_hash_alg_t alg, const pt_iovec_t *iov, size_t n, uint8_t *out);

/**
 * @brief Validate a public point: coordinates < p, on the curve, not the point at infinity.
 * @return PT_OK or PT_ERR_INVALID.
 */
pt_err_t pt_p521_point_check(const pt_p521_point_t *p);

/**
 * @brief Validate a private scalar: 1 <= d < n.
 * @return PT_OK or PT_ERR_INVALID.
 */
pt_err_t pt_p521_scalar_check(const uint8_t d[PT_P521_LEN]);

/**
 * @brief Generate a key pair.
 * @return PT_OK, PT_ERR_STATE without RNG, PT_ERR_CRYPTO.
 */
pt_err_t pt_p521_keygen(uint8_t d[PT_P521_LEN], pt_p521_point_t *pub);

/**
 * @brief Compute the public point d*G of a private scalar (used to validate stored keys).
 * @return PT_OK, PT_ERR_INVALID, PT_ERR_STATE without RNG, PT_ERR_CRYPTO.
 */
pt_err_t pt_p521_public(const uint8_t d[PT_P521_LEN], pt_p521_point_t *pub);

/**
 * @brief McCallum-Relyea server step: out = d * in.
 *
 * @p in is validated (on curve, not infinity) and the result must not be the point at
 * infinity. The scalar multiplication uses randomised projective coordinates (side-channel
 * countermeasure), so an RNG must be registered.
 *
 * @return PT_OK, PT_ERR_INVALID for a bad input point or scalar, PT_ERR_STATE without RNG,
 *         PT_ERR_CRYPTO.
 */
pt_err_t pt_p521_ecmr(const uint8_t d[PT_P521_LEN], const pt_p521_point_t *in,
                      pt_p521_point_t *out);

/**
 * @brief ES512 signature (ECDSA P-521 with SHA-512, RFC 7518 section 3.4) over the
 *        concatenation of @p n fragments. Deterministic nonces (RFC 6979), with the RNG used
 *        for blinding.
 * @param sig Receives r || s, each 66 bytes big-endian.
 */
pt_err_t pt_es512_sign(const uint8_t d[PT_P521_LEN], const pt_iovec_t *msg, size_t n,
                       uint8_t sig[PT_ES512_SIG_LEN]);

/**
 * @brief Verify an ES512 signature.
 * @return PT_OK if valid, PT_ERR_INVALID if not.
 */
pt_err_t pt_es512_verify(const pt_p521_point_t *pub, const pt_iovec_t *msg, size_t n,
                         const uint8_t sig[PT_ES512_SIG_LEN]);

/**
 * @brief PBKDF2-HMAC-SHA256 (RFC 8018) for admin password hashing.
 * @return PT_OK, PT_ERR_INVALID (zero iterations or lengths), PT_ERR_CRYPTO.
 */
pt_err_t pt_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
                          uint32_t iterations, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif /* PT_CRYPTO_H */
