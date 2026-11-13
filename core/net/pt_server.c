/*
 * Event-driven HTTP server on BSD sockets; see pt_server.h for the design rationale.
 */
#include "pt/pt_server.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void conn_close(pt_srv_conn_t *c)
{
    if (c->fd >= 0) {
        close(c->fd);
    }
    pt_zeroize(c->buf, c->have); /* may contain request bodies */
    c->fd = -1;
    c->have = 0;
    c->peer_addr = 0;
}

/* Send everything within the configured send timeout. */
static bool send_all(const pt_srv_t *s, int fd, const char *data, size_t len)
{
    uint64_t deadline = now_ms() + s->cfg.send_timeout_ms;
    while (len > 0) {
        ssize_t n = send(fd, data, len, MSG_DONTWAIT);
        if (n > 0) {
            data += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return false;
        }
        uint64_t now = now_ms();
        if (now >= deadline) {
            return false;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        uint64_t left = deadline - now;
        struct timeval tv = {.tv_sec = (long)(left / 1000), .tv_usec = (long)(left % 1000) * 1000};
        if (select(fd + 1, NULL, &wfds, NULL, &tv) < 0 && errno != EINTR) {
            return false;
        }
    }
    return true;
}

static void reply(const pt_srv_t *s, int fd, const pt_srv_response_t *r)
{
    char head[1024];
    size_t extra = r->headers ? strlen(r->headers) : 0;
    if (extra > 768) {
        return; /* handler bug: refuse rather than truncate headers */
    }
    size_t n = pt_http_write_head(head, sizeof(head) - extra, r->status, r->content_type,
                                  r->body_len, false);
    if (n == 0) {
        return;
    }
    if (extra > 0) {
        /* insert extra header lines before the terminating empty line */
        memmove(head + n - 2 + extra, head + n - 2, 2);
        memcpy(head + n - 2, r->headers, extra);
        n += extra;
    }
    if (send_all(s, fd, head, n) && r->body_len > 0) {
        (void)send_all(s, fd, r->body, r->body_len);
    }
}

static void reject(pt_srv_t *s, pt_srv_conn_t *c, int status)
{
    pt_srv_response_t r = {.status = status};
    reply(s, c->fd, &r);
    if (s->cfg.on_reject != NULL) {
        char peer[16];
        struct in_addr a = {.s_addr = c->peer_addr};
        inet_ntop(AF_INET, &a, peer, sizeof(peer));
        s->cfg.on_reject(s->cfg.ctx, status, peer);
    }
    conn_close(c);
}

pt_err_t pt_srv_open(pt_srv_t *s, const pt_srv_config_t *cfg)
{
    memset(s, 0, sizeof(*s));
    for (unsigned i = 0; i < PT_SRV_MAX_CONNS; i++) {
        s->conns[i].fd = -1;
    }
    for (unsigned i = 0; i < PT_SRV_MAX_PORTS; i++) {
        s->listen_fd[i] = -1;
    }
    if (cfg == NULL || cfg->handler == NULL || cfg->ports[0] == 0 || cfg->max_conns == 0 ||
        cfg->max_conns > PT_SRV_MAX_CONNS || cfg->max_per_peer == 0 ||
        cfg->max_per_peer > cfg->max_conns || cfg->request_timeout_ms == 0) {
        return PT_ERR_INVALID;
    }
    s->cfg = *cfg;
    if (s->cfg.send_timeout_ms == 0) {
        s->cfg.send_timeout_ms = 5000;
    }
    for (unsigned i = 0; i < PT_SRV_MAX_PORTS; i++) {
        if (cfg->ports[i] == 0) {
            continue;
        }
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            pt_srv_close(s);
            return PT_ERR_STATE;
        }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(cfg->ports[i]);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        if (cfg->bind_addr != NULL && inet_pton(AF_INET, cfg->bind_addr, &sa.sin_addr) != 1) {
            close(fd);
            pt_srv_close(s);
            return PT_ERR_INVALID;
        }
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 8) != 0 ||
            set_nonblock(fd) != 0) {
            close(fd);
            pt_srv_close(s);
            return PT_ERR_STATE;
        }
        s->listen_fd[i] = fd;
    }
    return PT_OK;
}

void pt_srv_close(pt_srv_t *s)
{
    for (unsigned i = 0; i < PT_SRV_MAX_CONNS; i++) {
        if (s->conns[i].fd >= 0) {
            conn_close(&s->conns[i]);
        }
    }
    for (unsigned i = 0; i < PT_SRV_MAX_PORTS; i++) {
        if (s->listen_fd[i] >= 0) {
            close(s->listen_fd[i]);
            s->listen_fd[i] = -1;
        }
    }
}

unsigned pt_srv_active(const pt_srv_t *s)
{
    unsigned n = 0;
    for (unsigned i = 0; i < s->cfg.max_conns; i++) {
        n += s->conns[i].fd >= 0;
    }
    return n;
}

static void do_accept(pt_srv_t *s, int lfd)
{
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = accept(lfd, (struct sockaddr *)&peer, &plen);
    if (fd < 0) {
        return;
    }
    if (set_nonblock(fd) != 0) {
        close(fd);
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* Per-peer cap. */
    unsigned same = 0;
    for (unsigned i = 0; i < s->cfg.max_conns; i++) {
        same += s->conns[i].fd >= 0 && s->conns[i].peer_addr == peer.sin_addr.s_addr;
    }
    if (same >= s->cfg.max_per_peer) {
        close(fd);
        s->evicted++;
        return;
    }
    /* Free slot, or evict the oldest connection (all are incomplete by construction). */
    pt_srv_conn_t *slot = NULL;
    pt_srv_conn_t *oldest = NULL;
    for (unsigned i = 0; i < s->cfg.max_conns; i++) {
        pt_srv_conn_t *c = &s->conns[i];
        if (c->fd < 0) {
            slot = c;
            break;
        }
        if (oldest == NULL || c->accepted_ms < oldest->accepted_ms) {
            oldest = c;
        }
    }
    if (slot == NULL) {
        if (oldest == NULL) { /* only possible with max_conns == 0, rejected by pt_srv_open */
            close(fd);
            return;
        }
        conn_close(oldest);
        s->evicted++;
        slot = oldest;
    }
    slot->fd = fd;
    slot->accepted_ms = now_ms();
    slot->peer_addr = peer.sin_addr.s_addr;
    slot->have = 0;
    s->accepted++;
}

static void dispatch(pt_srv_t *s, pt_srv_conn_t *c, const pt_http_req_t *h)
{
    pt_srv_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = h->method;
    req.target = h->target;
    req.target_len = h->target_len;
    req.head = c->buf;
    req.head_len = h->head_len;
    req.body = (const uint8_t *)c->buf + h->head_len;
    req.body_len = h->content_length;
    struct in_addr a = {.s_addr = c->peer_addr};
    inet_ntop(AF_INET, &a, req.peer, sizeof(req.peer));
    struct sockaddr_in local;
    socklen_t llen = sizeof(local);
    if (getsockname(c->fd, (struct sockaddr *)&local, &llen) == 0) {
        inet_ntop(AF_INET, &local.sin_addr, req.local, sizeof(req.local));
        req.local_port = ntohs(local.sin_port);
    }
    pt_srv_response_t resp = {.status = 500};
    s->cfg.handler(s->cfg.ctx, &req, &resp);
    reply(s, c->fd, &resp);
    conn_close(c);
}

static void do_read(pt_srv_t *s, pt_srv_conn_t *c)
{
    size_t cap = sizeof(c->buf);
    for (;;) {
        if (c->have >= cap) {
            reject(s, c, 413);
            return;
        }
        ssize_t n = recv(c->fd, c->buf + c->have, cap - c->have, MSG_DONTWAIT);
        if (n == 0) {
            conn_close(c); /* peer closed before completing a request */
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                break;
            }
            conn_close(c);
            return;
        }
        c->have += (size_t)n;
    }
    pt_http_req_t h;
    int rc = pt_http_parse_head(c->buf, c->have, PT_SRV_MAX_BODY, &h);
    if (rc == PT_HTTP_NEED_MORE) {
        return;
    }
    if (rc < 0) {
        reject(s, c, -rc);
        return;
    }
    if (c->have < h.head_len + h.content_length) {
        return; /* body incomplete */
    }
    dispatch(s, c, &h);
}

void pt_srv_poll(pt_srv_t *s, uint32_t timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    int maxfd = -1;
    for (unsigned i = 0; i < PT_SRV_MAX_PORTS; i++) {
        if (s->listen_fd[i] >= 0) {
            FD_SET(s->listen_fd[i], &rfds);
            maxfd = s->listen_fd[i] > maxfd ? s->listen_fd[i] : maxfd;
        }
    }
    for (unsigned i = 0; i < s->cfg.max_conns; i++) {
        if (s->conns[i].fd >= 0) {
            FD_SET(s->conns[i].fd, &rfds);
            maxfd = s->conns[i].fd > maxfd ? s->conns[i].fd : maxfd;
        }
    }
    struct timeval tv = {.tv_sec = (long)(timeout_ms / 1000),
                         .tv_usec = (long)(timeout_ms % 1000) * 1000};
    int ready = maxfd >= 0 ? select(maxfd + 1, &rfds, NULL, NULL, &tv) : 0;
    if (ready > 0) {
        for (unsigned i = 0; i < s->cfg.max_conns; i++) {
            if (s->conns[i].fd >= 0 && FD_ISSET(s->conns[i].fd, &rfds)) {
                do_read(s, &s->conns[i]);
            }
        }
        for (unsigned i = 0; i < PT_SRV_MAX_PORTS; i++) {
            if (s->listen_fd[i] >= 0 && FD_ISSET(s->listen_fd[i], &rfds)) {
                do_accept(s, s->listen_fd[i]);
            }
        }
    }
    /* Deadlines */
    uint64_t now = now_ms();
    for (unsigned i = 0; i < s->cfg.max_conns; i++) {
        pt_srv_conn_t *c = &s->conns[i];
        if (c->fd >= 0 && now - c->accepted_ms > s->cfg.request_timeout_ms) {
            s->timeouts++;
            reject(s, c, 408);
        }
    }
}
