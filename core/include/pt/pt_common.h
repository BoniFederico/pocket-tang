/**
 * @file pt_common.h
 * @brief Shared definitions for the portable Pocket Tang core: error codes, size limits and
 *        constant-time helpers.
 *
 * The core never allocates memory dynamically in the request path. Every function takes
 * caller-provided buffers and explicit capacities, and fails closed on any limit violation.
 */
#ifndef PT_COMMON_H
#define PT_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Result codes. Zero is success; everything else is a failure that callers must not ignore. */
typedef enum pt_err {
    PT_OK = 0,
    PT_ERR_INVALID = 1,    /**< Malformed input (syntax, encoding, value out of range). */
    PT_ERR_NOSPACE = 2,    /**< Output buffer or token array too small. */
    PT_ERR_LIMIT = 3,      /**< A hard size/depth/count limit was exceeded. */
    PT_ERR_NOTFOUND = 4,   /**< Requested element or key does not exist. */
    PT_ERR_DUPLICATE = 5,  /**< A JSON member that must be unique appeared twice. */
    PT_ERR_CRYPTO = 6,     /**< Cryptographic backend failure. */
    PT_ERR_FORBIDDEN = 7,  /**< Key lacks the required permission (key_ops/use). */
    PT_ERR_STATE = 8,      /**< Operation not valid in the current state. */
    PT_ERR_UNSUPPORTED = 9 /**< Valid but unsupported (e.g. other curve or algorithm). */
} pt_err_t;

/** Byte length of a P-521 coordinate or scalar as used by JOSE (fixed-width, big-endian). */
#define PT_P521_LEN 66
/** Byte length of an ES512 raw signature (r || s). */
#define PT_ES512_SIG_LEN (2 * PT_P521_LEN)
/** Base64url length of a 66-byte coordinate (no padding). */
#define PT_P521_B64_LEN 88

/** Maximum base64url thumbprint length (SHA-512 -> 64 bytes -> 86 chars) plus NUL. */
#define PT_THP_MAX 87

/** Maximum length of a thumbprint-style key id accepted from a URL. */
#define PT_KID_MAX 86

/**
 * @brief Constant-time memory comparison.
 * @return true when both buffers hold the same @p len bytes. Execution time does not depend on
 *         the data, only on @p len.
 */
bool pt_ct_memeq(const void *a, const void *b, size_t len);

/**
 * @brief Overwrite a buffer with zeros in a way the compiler must not optimise away.
 */
void pt_zeroize(void *buf, size_t len);

/**
 * @brief Human readable name of an error code, for logs and tests. Never NULL.
 */
const char *pt_err_str(pt_err_t err);

#ifdef __cplusplus
}
#endif
#endif /* PT_COMMON_H */
