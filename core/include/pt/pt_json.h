/**
 * @file pt_json.h
 * @brief Strict, bounded, non-recursive JSON tokenizer and a bounded JSON writer.
 *
 * Design (see ADR-0002):
 *  - The parser produces a flat token array (similar to jsmn) in caller memory. No heap, no
 *    recursion; nesting is limited to #PT_JSON_MAX_DEPTH and the token array to the caller's
 *    capacity. Any violation fails the whole parse (fail closed).
 *  - Grammar is RFC 8259 with no extensions: only `"` keys, no trailing commas, no comments,
 *    strict number syntax, only `true`/`false`/`null` literals, valid UTF-8, no raw control
 *    characters in strings, only the standard escapes.
 *  - Numbers are tokenized but never evaluated: the Tang protocol has no numeric members.
 *  - Member lookup reports duplicate keys as an error.
 *
 * Token layout follows the document order. An object token's @c size is its member count; each
 * key token has @c size 1 and the value token follows it immediately; an array token's @c size is
 * its element count.
 */
#ifndef PT_JSON_H
#define PT_JSON_H

#include "pt/pt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum container nesting accepted by the parser. */
#define PT_JSON_MAX_DEPTH 8
/** Maximum input size accepted by the parser (bytes). */
#define PT_JSON_MAX_INPUT 16384

/** Token types. */
typedef enum pt_json_type {
    PT_JSON_UNDEF = 0,
    PT_JSON_OBJECT = 1,
    PT_JSON_ARRAY = 2,
    PT_JSON_STRING = 3,
    PT_JSON_PRIMITIVE = 4 /**< number, true, false or null */
} pt_json_type_t;

/** Token flags. */
#define PT_JSON_F_KEY     0x1u /**< String token is an object key. */
#define PT_JSON_F_ESCAPED 0x2u /**< String token contains at least one backslash escape. */

/** One token. Offsets are relative to the parsed buffer. For strings they exclude the quotes. */
typedef struct pt_json_tok {
    uint16_t type;  /**< pt_json_type_t */
    uint16_t size;  /**< number of children (see file comment) */
    uint16_t flags; /**< PT_JSON_F_* */
    int16_t parent; /**< parent token index or -1 for the root */
    uint32_t start; /**< first byte offset */
    uint32_t end;   /**< one past the last byte offset */
} pt_json_tok_t;

/** A parsed document: the input buffer plus its token array. */
typedef struct pt_json_doc {
    const char *buf;
    size_t len;
    pt_json_tok_t *toks;
    int count;
} pt_json_doc_t;

/**
 * @brief Parse a complete JSON text.
 *
 * @param buf   Input bytes (need not be NUL-terminated).
 * @param len   Input length; must be <= PT_JSON_MAX_INPUT.
 * @param toks  Caller-provided token array.
 * @param cap   Capacity of @p toks (max 32767).
 * @param doc   Receives the document descriptor on success.
 * @return PT_OK; PT_ERR_INVALID on any syntax violation; PT_ERR_LIMIT on depth/size limits;
 *         PT_ERR_NOSPACE if more than @p cap tokens are needed.
 */
pt_err_t pt_json_parse(const char *buf, size_t len, pt_json_tok_t *toks, unsigned cap,
                       pt_json_doc_t *doc);

/**
 * @brief Index of the token following the whole subtree rooted at @p tok.
 * @return Index (may equal doc->count when @p tok is the last subtree).
 */
int pt_json_skip(const pt_json_doc_t *doc, int tok);

/**
 * @brief Look up a member of an object.
 * @return Value token index (>= 0); -PT_ERR_NOTFOUND if absent; -PT_ERR_DUPLICATE if the key
 *         appears more than once; -PT_ERR_INVALID if @p obj is not an object.
 */
int pt_json_obj_get(const pt_json_doc_t *doc, int obj, const char *key);

/**
 * @brief Element of an array by position.
 * @return Token index (>= 0) or -PT_ERR_NOTFOUND / -PT_ERR_INVALID.
 */
int pt_json_arr_get(const pt_json_doc_t *doc, int arr, unsigned idx);

/**
 * @brief Compare a string token (after unescaping) with a NUL-terminated literal.
 * @return true on exact match. Non-string tokens never match.
 */
bool pt_json_str_eq(const pt_json_doc_t *doc, int tok, const char *lit);

/**
 * @brief Copy a string token, unescaped and NUL-terminated, into @p out.
 * @param out_len Optional; receives the number of bytes written (excluding NUL).
 * @return PT_OK, PT_ERR_INVALID if @p tok is not a string or has an invalid escape sequence,
 *         PT_ERR_NOSPACE if @p cap is too small.
 */
pt_err_t pt_json_str_get(const pt_json_doc_t *doc, int tok, char *out, size_t cap, size_t *out_len);

/**
 * @brief Return true if @p arr is an array containing a string equal to @p lit.
 */
bool pt_json_arr_has_str(const pt_json_doc_t *doc, int arr, const char *lit);

/** @brief Type of a token, or PT_JSON_UNDEF for an out-of-range index. */
pt_json_type_t pt_json_type(const pt_json_doc_t *doc, int tok);

/* ------------------------------------------------------------------------------------------ */

/**
 * @brief Bounded JSON writer. All write functions are no-ops once an error is latched; check
 *        the result with pt_jw_finish().
 */
typedef struct pt_jw {
    char *buf;
    size_t cap;
    size_t len;
    pt_err_t err;
    uint8_t depth;
    uint8_t pending_key;
    uint8_t first[PT_JSON_MAX_DEPTH + 1];
} pt_jw_t;

/** @brief Initialise a writer over @p buf (capacity @p cap, including the final NUL). */
void pt_jw_init(pt_jw_t *w, char *buf, size_t cap);
/** @brief Begin an object value. */
void pt_jw_obj_begin(pt_jw_t *w);
/** @brief End the current object. */
void pt_jw_obj_end(pt_jw_t *w);
/** @brief Begin an array value. */
void pt_jw_arr_begin(pt_jw_t *w);
/** @brief End the current array. */
void pt_jw_arr_end(pt_jw_t *w);
/** @brief Emit an object key (with the separating comma and colon). */
void pt_jw_key(pt_jw_t *w, const char *key);
/** @brief Emit a string value (escaped as needed). */
void pt_jw_str(pt_jw_t *w, const char *s);
/** @brief Emit a string value of explicit length (escaped as needed). */
void pt_jw_strn(pt_jw_t *w, const char *s, size_t n);
/** @brief Emit a pre-serialised JSON value verbatim. */
void pt_jw_raw(pt_jw_t *w, const char *json, size_t n);
/** @brief Emit a quoted base64url string value of @p n bytes. */
void pt_jw_b64url(pt_jw_t *w, const uint8_t *data, size_t n);
/** @brief Emit an unsigned integer value. */
void pt_jw_uint(pt_jw_t *w, uint32_t v);
/** @brief Emit a boolean value. */
void pt_jw_bool(pt_jw_t *w, bool v);
/** @brief Emit a null value. */
void pt_jw_null(pt_jw_t *w);
/**
 * @brief Finish writing: NUL-terminate and report the first latched error.
 * @param len Optional; receives the number of bytes written (excluding NUL).
 * @return PT_OK, PT_ERR_NOSPACE if the buffer overflowed, PT_ERR_STATE on unbalanced nesting.
 */
pt_err_t pt_jw_finish(pt_jw_t *w, size_t *len);

#ifdef __cplusplus
}
#endif
#endif /* PT_JSON_H */
