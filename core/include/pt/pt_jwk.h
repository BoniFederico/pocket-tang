/**
 * @file pt_jwk.h
 * @brief JSON Web Keys (RFC 7517/7518) restricted to EC P-521, RFC 7638 thumbprints and the
 *        key-permission rules of the jose library used by upstream tang/clevis.
 */
#ifndef PT_JWK_H
#define PT_JWK_H

#include "pt/pt_common.h"
#include "pt/pt_crypto.h"
#include "pt/pt_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/** JOSE algorithms the server knows about. */
typedef enum pt_alg {
    PT_ALG_NONE = 0,  /**< "alg" member absent */
    PT_ALG_ES512 = 1, /**< ECDSA P-521 SHA-512 signing key */
    PT_ALG_ECMR = 2,  /**< McCallum-Relyea exchange key */
    PT_ALG_OTHER = 3  /**< any other value */
} pt_alg_t;

/** Key operations (RFC 7517 section 4.3) relevant to tang. */
typedef enum pt_keyop {
    PT_OP_SIGN = 0,
    PT_OP_VERIFY = 1,
    PT_OP_DERIVE_KEY = 2,
} pt_keyop_t;

/** A parsed EC P-521 JWK. The private scalar is present only when @c has_d is true. */
typedef struct pt_jwk {
    pt_p521_point_t pub;
    uint8_t d[PT_P521_LEN];
    bool has_d;
    pt_alg_t alg;
} pt_jwk_t;

/**
 * @brief Return the jose_jwk_prm() verdict for operation @p op on the JWK object @p obj.
 *
 * Mirrors libjose: if neither "key_ops" nor "use" is present the result is !@p required;
 * otherwise the operation is permitted if "key_ops" is an array containing it, or if "use"
 * maps to it ("sig" -> sign/verify, "enc" -> encrypt/decrypt/wrapKey/unwrapKey). Malformed
 * members ("use" not a string) deny.
 */
bool pt_jwk_permits(const pt_json_doc_t *doc, int obj, bool required, pt_keyop_t op);

/**
 * @brief Classify the optional "alg" member of @p obj.
 * @return PT_OK with @p alg set, or PT_ERR_INVALID if "alg" is present but not a string or
 *         duplicated.
 */
pt_err_t pt_jwk_get_alg(const pt_json_doc_t *doc, int obj, pt_alg_t *alg);

/**
 * @brief Parse an EC P-521 JWK.
 *
 * Requires kty "EC", crv "P-521", x and y as canonical 66-byte base64url values forming a
 * valid curve point. "d" is accepted only when @p allow_private is true and must be a valid
 * scalar matching the public point. Duplicate members are rejected. Unknown members are
 * ignored.
 *
 * @return PT_OK, PT_ERR_INVALID (malformed, wrong kty/crv, off-curve...), PT_ERR_UNSUPPORTED
 *         (kty "EC" with a different curve), PT_ERR_FORBIDDEN ("d" present but not allowed).
 */
pt_err_t pt_jwk_parse(const pt_json_doc_t *doc, int obj, bool allow_private, pt_jwk_t *out);

/**
 * @brief Serialise the public part of a key as a JWK object into a JSON writer.
 *
 * Members are emitted in lexicographic order: alg (if not NONE), crv, key_ops (if
 * @p ops_mask is non-zero; bit i = pt_keyop_t i), kty, x, y.
 */
void pt_jwk_write_public(pt_jw_t *w, const pt_p521_point_t *pub, pt_alg_t alg, unsigned ops_mask);

/**
 * @brief Compute the RFC 7638 thumbprint of a P-521 public key with the given hash.
 *
 * The hash input is `{"crv":"P-521","kty":"EC","x":"...","y":"..."}`, which is what libjose
 * hashes for EC keys.
 *
 * @param out     Receives pt_hash_len(alg) bytes.
 */
pt_err_t pt_jwk_thumbprint(const pt_p521_point_t *pub, pt_hash_alg_t alg, uint8_t *out);

/**
 * @brief Thumbprint as an unpadded base64url string.
 * @param out Buffer of at least PT_THP_MAX bytes.
 */
pt_err_t pt_jwk_thumbprint_b64(const pt_p521_point_t *pub, pt_hash_alg_t alg, char *out,
                               size_t cap);

/** @brief Wipe a JWK (including the private scalar). */
void pt_jwk_wipe(pt_jwk_t *jwk);

#ifdef __cplusplus
}
#endif
#endif /* PT_JWK_H */
