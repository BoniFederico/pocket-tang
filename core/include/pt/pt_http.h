/**
 * @file pt_http.h
 * @brief Minimal, strict, bounded HTTP/1.1 request-head parser and response-head writer.
 *
 * Used by platform layers that do not have an HTTP server of their own (the host harness, the
 * future Raspberry Pi Pico layer). The ESP32 layer uses esp_http_server instead.
 *
 * Only what a Tang server needs is supported: a request line, headers, and an optional body
 * framed by Content-Length. Chunked transfer coding, obsolete line folding, absolute-form targets
 * and HTTP versions other than 1.0/1.1 are rejected.
 */
#ifndef PT_HTTP_H
#define PT_HTTP_H

#include "pt/pt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size of the request head (request line + headers + empty line). */
#define PT_HTTP_MAX_HEAD 2048
/** Maximum request-target length. */
#define PT_HTTP_MAX_TARGET 512
/** Maximum number of header fields. */
#define PT_HTTP_MAX_HEADERS 32

/** Parsed request head. Pointers refer into the parsed buffer. */
typedef struct pt_http_req {
    char method[8];     /**< NUL-terminated method token */
    const char *target; /**< request target (not NUL-terminated) */
    size_t target_len;
    int minor_version;     /**< 0 or 1 */
    size_t head_len;       /**< bytes consumed by the head, including the final CRLF CRLF */
    bool has_length;       /**< Content-Length present */
    size_t content_length; /**< value of Content-Length (0 if absent) */
    bool keep_alive;       /**< connection persistence requested/allowed */
} pt_http_req_t;

/** Additional result codes. */
#define PT_HTTP_NEED_MORE 1 /**< head incomplete: read more and call again */

/**
 * @brief Parse a request head from the start of @p buf.
 *
 * @return 0 on success, PT_HTTP_NEED_MORE if the terminating empty line has not been seen yet,
 *         or a negative HTTP status to answer with: -400 (malformed), -413 (Content-Length
 *         above @p max_body), -414 (target too long), -431 (head too large), -501
 * (Transfer-Encoding), -505 (version).
 */
int pt_http_parse_head(const char *buf, size_t len, size_t max_body, pt_http_req_t *req);

/**
 * @brief Find a header field in a request head that pt_http_parse_head() accepted.
 *
 * Case-insensitive match; @p name must be given in lower case. The value is returned without
 * surrounding whitespace.
 * @return true if found (first occurrence).
 */
bool pt_http_header(const char *head, size_t head_len, const char *name, const char **value,
                    size_t *value_len);

/** @brief Standard reason phrase for a status code ("Unknown" if not known). */
const char *pt_http_reason(int status);

/**
 * @brief Write a response head with Content-Length and optional Content-Type.
 * @return Number of bytes written, or 0 if @p cap is too small.
 */
size_t pt_http_write_head(char *out, size_t cap, int status, const char *content_type,
                          size_t content_length, bool keep_alive);

#ifdef __cplusplus
}
#endif
#endif /* PT_HTTP_H */
