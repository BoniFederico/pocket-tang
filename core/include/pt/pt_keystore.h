/**
 * @file pt_keystore.h
 * @brief Tang key store: active and rotated ES512/ECMR key pairs, thumbprint lookup and a
 *        versioned persistence format.
 *
 * Semantics follow upstream tang:
 *  - exactly one active ES512 (signing) key and one active ECMR (exchange) key are advertised;
 *  - rotation creates a new pair and marks the previous pair "rotated": rotated keys are no
 *    longer advertised, but stay usable for recovery (`/rec/{kid}`) and as an additional
 *    signer for `/adv/{kid}`, so existing Clevis bindings keep working;
 *  - a key is identified by its RFC 7638 thumbprint under any of S1, S224, S256, S384, S512.
 *
 * The store holds at most PT_KEYS_MAX keys; rotation fails with PT_ERR_LIMIT when full, and the
 * administrator must explicitly purge old rotated keys (which breaks bindings to them).
 */
#ifndef PT_KEYSTORE_H
#define PT_KEYSTORE_H

#include "pt/pt_common.h"
#include "pt/pt_crypto.h"
#include "pt/pt_jwk.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of keys (active + rotated). */
#define PT_KEYS_MAX 8

/** Serialised size of a key store blob with @p n keys. */
#define PT_KEYSTORE_BLOB_LEN(n) (8u + (size_t)(n) * (2u + 3u * PT_P521_LEN) + 32u)
/** Maximum blob size. */
#define PT_KEYSTORE_BLOB_MAX PT_KEYSTORE_BLOB_LEN(PT_KEYS_MAX)

/** One key. */
typedef struct pt_key {
    uint8_t d[PT_P521_LEN];
    pt_p521_point_t pub;
    pt_alg_t alg;                                /**< PT_ALG_ES512 or PT_ALG_ECMR */
    bool rotated;                                /**< true once superseded by a newer key */
    uint8_t thp[PT_HASH_COUNT][PT_HASH_MAX_LEN]; /**< cached raw thumbprints */
} pt_key_t;

/** The key store. Treat as opaque outside pt_keystore.c and pt_tang.c. */
typedef struct pt_keystore {
    pt_key_t keys[PT_KEYS_MAX];
    unsigned count;
    uint32_t generation; /**< incremented on every change; used to invalidate caches */
} pt_keystore_t;

/** @brief Initialise an empty store. */
void pt_keystore_init(pt_keystore_t *ks);

/** @brief Wipe all key material. */
void pt_keystore_wipe(pt_keystore_t *ks);

/**
 * @brief Generate the initial active key pair if the store has no active keys.
 * @return PT_OK (also if keys already exist), or a crypto error.
 */
pt_err_t pt_keystore_ensure(pt_keystore_t *ks);

/**
 * @brief Rotate: generate a new ES512 + ECMR pair and mark the current active pair rotated.
 * @return PT_OK, PT_ERR_LIMIT if fewer than two slots are free, or a crypto error. On error the
 *         store is unchanged.
 */
pt_err_t pt_keystore_rotate(pt_keystore_t *ks);

/**
 * @brief Delete one rotated key identified by any thumbprint.
 * @return PT_OK, PT_ERR_NOTFOUND, or PT_ERR_FORBIDDEN for an active key.
 */
pt_err_t pt_keystore_purge(pt_keystore_t *ks, const char *kid, size_t kid_len);

/** @brief Delete all rotated keys. @return number of keys removed. */
unsigned pt_keystore_purge_rotated(pt_keystore_t *ks);

/**
 * @brief Find a key by base64url thumbprint (any supported hash).
 * @return The key, or NULL if not found or @p kid is malformed.
 */
const pt_key_t *pt_keystore_find(const pt_keystore_t *ks, const char *kid, size_t kid_len);

/**
 * @brief Import an existing private JWK (e.g. a key file from an upstream tang key directory).
 *
 * @p jwk must have a private scalar and alg ES512 or ECMR. If @p rotated is false and an
 * active key with the same algorithm exists, that key is marked rotated.
 * @return PT_OK, PT_ERR_INVALID, PT_ERR_LIMIT (store full), PT_ERR_DUPLICATE (already present).
 */
pt_err_t pt_keystore_import(pt_keystore_t *ks, const pt_jwk_t *jwk, bool rotated);

/** @brief Number of keys in the store. */
unsigned pt_keystore_count(const pt_keystore_t *ks);

/** @brief Key at position @p i (0 <= i < count), oldest first; NULL if out of range. */
const pt_key_t *pt_keystore_at(const pt_keystore_t *ks, unsigned i);

/** @brief The active key with algorithm @p alg, or NULL. */
const pt_key_t *pt_keystore_active(const pt_keystore_t *ks, pt_alg_t alg);

/**
 * @brief Serialise the store (including private keys) for persistent storage.
 *
 * Format v1: "PTKS" | version(1) | count(1) | reserved(2) | count * (alg(1) | flags(1) | d | x | y)
 * | SHA-256 over all preceding bytes. The caller must store the blob in protected storage
 * (encrypted NVS on hardened devices) and wipe its buffer afterwards.
 *
 * @return PT_OK or PT_ERR_NOSPACE.
 */
pt_err_t pt_keystore_save(const pt_keystore_t *ks, uint8_t *out, size_t cap, size_t *len);

/**
 * @brief Load a store from a blob produced by pt_keystore_save().
 *
 * Verifies the checksum, every scalar range and point, and that each private scalar
 * matches its public point. Fails closed: on any error the store is left empty.
 */
pt_err_t pt_keystore_load(pt_keystore_t *ks, const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* PT_KEYSTORE_H */
