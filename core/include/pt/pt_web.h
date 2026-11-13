/**
 * @file pt_web.h
 * @brief Helpers for the setup/admin web UI: form-body parsing, HTML escaping, password hashing,
 *        sessions with CSRF tokens and login rate limiting.
 *
 * Portable and fuzzed; the platform layer only moves bytes between the HTTP server and these
 * functions. Time is passed in by the caller as seconds from any monotonic origin.
 */
#ifndef PT_WEB_H
#define PT_WEB_H

#include "pt/pt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------------------------ */
/* application/x-www-form-urlencoded                                                          */
/* ------------------------------------------------------------------------------------------ */

/** Maximum accepted form body size. */
#define PT_FORM_MAX 2048

/**
 * @brief Extract and decode one field of an urlencoded form body.
 *
 * Decodes `+` and `%XX`; rejects malformed percent escapes, encoded NUL bytes, control characters
 * other than tab, and fields that appear more than once (to avoid parameter-pollution
 * ambiguities). The output is NUL-terminated.
 *
 * @return PT_OK, PT_ERR_NOTFOUND (absent), PT_ERR_INVALID (malformed or duplicate),
 *         PT_ERR_NOSPACE (value longer than cap - 1), PT_ERR_LIMIT (body too large).
 */
pt_err_t pt_form_get(const char *body, size_t len, const char *name, char *out, size_t cap,
                     size_t *out_len);

/**
 * @brief HTML-escape @p in (`&`, `<`, `>`, `"`, `'`) into @p out (NUL-terminated).
 * @return PT_OK or PT_ERR_NOSPACE.
 */
pt_err_t pt_html_escape(const char *in, char *out, size_t cap);

/* ------------------------------------------------------------------------------------------ */
/* Passwords                                                                                   */
/* ------------------------------------------------------------------------------------------ */

#define PT_PW_MIN      8
#define PT_PW_MAX      64
#define PT_PW_SALT_LEN 16
#define PT_PW_HASH_LEN 32
/** Default PBKDF2 iteration count (tuned for ~0.3 s on an ESP32 with hardware SHA). */
#define PT_PW_ITER_DEFAULT 10000

/** A stored password verifier. */
typedef struct pt_pw {
    uint8_t salt[PT_PW_SALT_LEN];
    uint8_t hash[PT_PW_HASH_LEN];
    uint32_t iter;
} pt_pw_t;

/**
 * @brief Check the password policy: 8..64 bytes of printable ASCII or UTF-8, no control chars.
 */
bool pt_pw_acceptable(const char *pw, size_t len);

/** @brief Create a verifier with a fresh random salt. */
pt_err_t pt_pw_set(pt_pw_t *v, const char *pw, size_t len, uint32_t iter);

/** @brief Verify a password (constant-time comparison of the derived hash). */
bool pt_pw_check(const pt_pw_t *v, const char *pw, size_t len);

/* ------------------------------------------------------------------------------------------ */
/* Sessions and rate limiting                                                                  */
/* ------------------------------------------------------------------------------------------ */

/** Cookie name used for the admin session. */
#define PT_SESSION_COOKIE "ptsid"
/** Base64url length of a 16-byte token, plus NUL. */
#define PT_TOKEN_B64 23

/** A single admin session (a new login replaces the previous one). */
typedef struct pt_session {
    bool active;
    uint8_t token[16];
    uint8_t csrf[16];
    uint32_t expires;
} pt_session_t;

/**
 * @brief Start a new session valid for @p ttl seconds and return its cookie value and CSRF
 *        token as base64url strings.
 */
pt_err_t pt_session_new(pt_session_t *s, uint32_t now, uint32_t ttl, char cookie[PT_TOKEN_B64],
                        char csrf[PT_TOKEN_B64]);

/** @brief End the session and wipe its tokens. */
void pt_session_end(pt_session_t *s);

/**
 * @brief Validate a `Cookie` request header against the session (constant time); refreshes
 *        nothing. Returns false if expired, absent or wrong.
 */
bool pt_session_check_cookie(const pt_session_t *s, const char *cookie_header, uint32_t now);

/** @brief Validate a CSRF token submitted with a form (constant time). */
bool pt_session_check_csrf(const pt_session_t *s, const char *token, size_t len);

/** Login rate limiter: exponential back-off after repeated failures. */
typedef struct pt_ratelimit {
    uint32_t failures;
    uint32_t blocked_until;
} pt_ratelimit_t;

/** @brief True if a login attempt is allowed now. */
bool pt_ratelimit_allowed(const pt_ratelimit_t *r, uint32_t now);
/** @brief Record a failed attempt: from the third failure on, block 5 s, doubling, max 300 s. */
void pt_ratelimit_fail(pt_ratelimit_t *r, uint32_t now);
/** @brief Reset after a successful login. */
void pt_ratelimit_ok(pt_ratelimit_t *r);

#ifdef __cplusplus
}
#endif
#endif /* PT_WEB_H */
