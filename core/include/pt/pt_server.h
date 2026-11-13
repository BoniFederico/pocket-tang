/**
 * @file pt_server.h
 * @brief Small event-driven HTTP/1.1 server on BSD sockets (POSIX or lwIP).
 *
 * Why not the platform's HTTP server: a server that reads request heads with blocking receives
 * on a single task can be stalled by one client that sends a byte per second ("slowloris").
 * This server never blocks on a single connection:
 *
 *  - every socket is non-blocking and multiplexed with select();
 *  - a request must be complete (head + body) within a total deadline, otherwise it gets 408;
 *  - the number of connections is bounded, with a per-peer cap; when full, the oldest
 *    incomplete connection is evicted;
 *  - request heads and bodies are bounded and parsed by the fuzzed pt_http parser;
 *  - one request per connection (`Connection: close`), which is all Tang clients need.
 *
 * Complete requests are passed to a synchronous handler on the polling thread. A slow handler
 * (a P-521 operation takes ~0.5 s on an ESP32) delays other connections but cannot be abused to
 * hold them: incomplete requests keep timing out independently.
 *
 * The server uses only BSD sockets and clock_gettime(), so it builds unchanged for the Linux
 * host harness and for ESP-IDF/lwIP; it contains no platform-specific code.
 */
#ifndef PT_SERVER_H
#define PT_SERVER_H

#include "pt/pt_common.h"
#include "pt/pt_http.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum simultaneous connections per server. */
#ifndef PT_SRV_MAX_CONNS
#define PT_SRV_MAX_CONNS 6
#endif
/** Maximum request body. */
#ifndef PT_SRV_MAX_BODY
#define PT_SRV_MAX_BODY 2048
#endif
/** Maximum listening ports per server. */
#define PT_SRV_MAX_PORTS 2

/** A complete request handed to the handler. All pointers are valid during the call only. */
typedef struct pt_srv_request {
    const char *method; /**< NUL-terminated */
    const char *target; /**< not NUL-terminated */
    size_t target_len;
    const char *head; /**< raw head, for pt_http_header() */
    size_t head_len;
    const uint8_t *body;
    size_t body_len;
    char peer[16];  /**< client IPv4 address */
    char local[16]; /**< local IPv4 address the request arrived on */
    uint16_t local_port;
} pt_srv_request_t;

/** Response filled in by the handler. */
typedef struct pt_srv_response {
    int status;
    const char *content_type; /**< NULL for no Content-Type */
    const char *headers;      /**< extra header lines ending in CRLF, max 768 bytes; or NULL */
    const char *body;
    size_t body_len;
} pt_srv_response_t;

typedef void (*pt_srv_handler_fn)(void *ctx, const pt_srv_request_t *req, pt_srv_response_t *resp);

/** Optional notification of requests rejected by the server itself (408, 413, 431, ...). */
typedef void (*pt_srv_reject_fn)(void *ctx, int status, const char *peer);

typedef struct pt_srv_config {
    uint16_t ports[PT_SRV_MAX_PORTS]; /**< 0 = unused; at least one required */
    const char *bind_addr;            /**< IPv4 address or NULL for any */
    unsigned max_conns;               /**< 1..PT_SRV_MAX_CONNS */
    unsigned max_per_peer;            /**< 1..max_conns */
    uint32_t request_timeout_ms;      /**< total time to receive head + body */
    uint32_t send_timeout_ms;         /**< total time to send the response */
    pt_srv_handler_fn handler;
    pt_srv_reject_fn on_reject;
    void *ctx;
} pt_srv_config_t;

/** Connection state (internal). */
typedef struct pt_srv_conn {
    int fd;
    uint64_t accepted_ms;
    uint32_t peer_addr;
    size_t have;
    char buf[PT_HTTP_MAX_HEAD + PT_SRV_MAX_BODY];
} pt_srv_conn_t;

/** Server state. Allocate statically; treat as opaque. */
typedef struct pt_srv {
    pt_srv_config_t cfg;
    int listen_fd[PT_SRV_MAX_PORTS];
    pt_srv_conn_t conns[PT_SRV_MAX_CONNS];
    uint32_t accepted;
    uint32_t evicted;
    uint32_t timeouts;
} pt_srv_t;

/**
 * @brief Create the listening sockets.
 * @return PT_OK, PT_ERR_INVALID (bad config), PT_ERR_STATE (socket/bind/listen failed).
 */
pt_err_t pt_srv_open(pt_srv_t *s, const pt_srv_config_t *cfg);

/**
 * @brief Wait up to @p timeout_ms for activity, then accept, read, time out, dispatch and
 *        answer as needed. Call in a loop from a dedicated task/thread.
 */
void pt_srv_poll(pt_srv_t *s, uint32_t timeout_ms);

/** @brief Close all sockets. */
void pt_srv_close(pt_srv_t *s);

/** @brief Number of currently open client connections. */
unsigned pt_srv_active(const pt_srv_t *s);

#ifdef __cplusplus
}
#endif
#endif /* PT_SERVER_H */
