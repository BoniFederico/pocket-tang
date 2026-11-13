/**
 * @file pt_b64url.h
 * @brief Base64url (RFC 4648 section 5) without padding, as used by JOSE (RFC 7515 section 2).
 */
#ifndef PT_B64URL_H
#define PT_B64URL_H

#include "pt/pt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Encoded length (without NUL) for @p n input bytes. */
#define PT_B64URL_ENC_LEN(n) ((((size_t)(n)) * 4 + 2) / 3)

/**
 * @brief Encode bytes as unpadded base64url.
 * @param in      Input bytes.
 * @param in_len  Number of input bytes.
 * @param out     Output buffer; receives the encoding followed by a NUL byte.
 * @param cap     Capacity of @p out in bytes (must be >= PT_B64URL_ENC_LEN(in_len) + 1).
 * @param out_len Optional; receives the number of characters written (excluding NUL).
 * @return PT_OK or PT_ERR_NOSPACE.
 */
pt_err_t pt_b64url_encode(const uint8_t *in, size_t in_len, char *out, size_t cap, size_t *out_len);

/**
 * @brief Decode unpadded base64url.
 *
 * Strict: rejects padding characters, whitespace, the standard base64 characters `+` and `/`,
 * a trailing single character (impossible length) and non-zero unused trailing bits
 * (non-canonical encodings).
 *
 * @param in      Encoded characters (not necessarily NUL-terminated).
 * @param in_len  Number of characters.
 * @param out     Output buffer.
 * @param cap     Capacity of @p out.
 * @param out_len Receives the number of decoded bytes.
 * @return PT_OK, PT_ERR_INVALID on malformed input, PT_ERR_NOSPACE if @p cap is too small.
 */
pt_err_t pt_b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t cap, size_t *out_len);

/**
 * @brief Decode a base64url string that must produce exactly @p want bytes.
 * @return PT_OK, or PT_ERR_INVALID if the decoded length differs or the input is malformed.
 */
pt_err_t pt_b64url_decode_exact(const char *in, size_t in_len, uint8_t *out, size_t want);

/**
 * @brief Return true if @p c belongs to the base64url alphabet.
 */
bool pt_b64url_is_char(char c);

#ifdef __cplusplus
}
#endif
#endif /* PT_B64URL_H */
