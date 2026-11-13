/**
 * @file pt_tang.h
 * @brief Tang protocol engine: request routing, the advertisement cache and key recovery.
 *
 * The engine is transport-agnostic. A platform HTTP server classifies a request with
 * pt_tang_route(), reads the body (bounded by PT_TANG_MAX_BODY) and calls pt_tang_handle(),
 * which writes the response body into a caller buffer. Status codes, content types and
 * validation order mirror upstream tangd (latchset/tang) so that clients observe identical
 * behaviour.
 *
 * Concurrency: a pt_tang_t is not internally synchronised. The platform must serialise all
 * calls that touch the same instance (Pocket Tang runs them on a single crypto worker task).
 * `/adv` responses are assembled from a precomputed cache and involve no public-key
 * operations; `/rec` performs one P-521 scalar multiplication.
 */
#ifndef PT_TANG_H
#define PT_TANG_H

#include "pt/pt_common.h"
#include "pt/pt_keystore.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum accepted request body (bytes). Larger bodies get 413. */
#define PT_TANG_MAX_BODY 2048
/** Recommended response buffer size; enough for /adv/{kid} with every key signing. */
#define PT_TANG_RESP_MAX 4096

/** Base64url payload capacity of the advertisement cache. */
#define PT_TANG_ADV_PAYLOAD_MAX 1600

/** Routes. */
typedef enum pt_route {
    PT_ROUTE_NONE = 0,    /**< no route matched: 404 */
    PT_ROUTE_ADV = 1,     /**< GET /adv */
    PT_ROUTE_ADV_KID = 2, /**< GET /adv/{kid} */
    PT_ROUTE_REC = 3,     /**< POST /rec/{kid} */
    PT_ROUTE_VERSION = 4  /**< GET /version */
} pt_route_t;

/** Result of routing a request line. */
typedef struct pt_tang_req {
    pt_route_t route;
    int status;               /**< 0 when routable, else 404 or 405 */
    char kid[PT_KID_MAX + 1]; /**< NUL-terminated kid for ADV_KID / REC */
    size_t kid_len;
} pt_tang_req_t;

/** A response produced by the engine. */
typedef struct pt_tang_resp {
    int status;               /**< HTTP status code */
    const char *content_type; /**< NULL when there is no body */
    size_t body_len;          /**< bytes written to the caller's buffer */
} pt_tang_resp_t;

/** Events reported to the platform (statistics, MQTT, logs). */
typedef enum pt_tang_event {
    PT_EV_REC_OK = 1,     /**< successful recovery */
    PT_EV_REC_DENIED = 2, /**< /rec refused (bad request, unknown kid, lock...) */
    PT_EV_ADV = 3         /**< advertisement served */
} pt_tang_event_t;

/** Event callback; @p kid may be empty. Must not block. */
typedef void (*pt_tang_event_cb)(void *ctx, pt_tang_event_t ev, int status, const char *kid);

/** Engine state. Treat as opaque. */
typedef struct pt_tang {
    pt_keystore_t ks;
    uint32_t adv_generation; /**< keystore generation the cache was built for */
    bool adv_valid;
    char payload_b64[PT_TANG_ADV_PAYLOAD_MAX];
    size_t payload_b64_len;
    uint8_t sig[PT_KEYS_MAX][PT_ES512_SIG_LEN]; /**< per-key signature (ES512 keys only) */
    bool locked;                                /**< kill switch: refuse /rec */
    bool include_tang_pub; /**< add "tang_pub" to /rec replies (upstream tang >= 15) */
    pt_tang_event_cb cb;
    void *cb_ctx;
} pt_tang_t;

/** @brief Initialise an engine with an empty key store. */
void pt_tang_init(pt_tang_t *t);

/** @brief Wipe all secrets held by the engine. */
void pt_tang_wipe(pt_tang_t *t);

/** @brief Access the key store (for load/save/rotate). Call pt_tang_refresh() after changes. */
pt_keystore_t *pt_tang_keystore(pt_tang_t *t);

/**
 * @brief Rebuild the advertisement cache if the key store changed.
 *
 * Signs the advertisement payload once with every ES512 key (active and rotated). Signatures
 * are deterministic, so this is idempotent.
 * @return PT_OK or an error (the cache is then invalid and /adv answers 500).
 */
pt_err_t pt_tang_refresh(pt_tang_t *t);

/** @brief Set the event callback. */
void pt_tang_set_event_cb(pt_tang_t *t, pt_tang_event_cb cb, void *ctx);

/** @brief Enable or disable the /rec kill switch. */
void pt_tang_set_locked(pt_tang_t *t, bool locked);

/**
 * @brief Classify a request.
 * @param method  HTTP method (case-sensitive, e.g. "GET").
 * @param target  Request target as received (path plus optional query); need not be
 *                NUL-terminated.
 * @param len     Length of @p target.
 */
void pt_tang_route(const char *method, const char *target, size_t len, pt_tang_req_t *req);

/**
 * @brief Handle a routed request.
 *
 * @param req      Result of pt_tang_route() (with status 0).
 * @param body     Request body (only used for /rec).
 * @param body_len Body length; > PT_TANG_MAX_BODY yields 413.
 * @param out      Response body buffer.
 * @param cap      Capacity of @p out (PT_TANG_RESP_MAX recommended).
 * @param resp     Receives the status, content type and body length.
 */
void pt_tang_handle(pt_tang_t *t, const pt_tang_req_t *req, const uint8_t *body, size_t body_len,
                    char *out, size_t cap, pt_tang_resp_t *resp);

#ifdef __cplusplus
}
#endif
#endif /* PT_TANG_H */
