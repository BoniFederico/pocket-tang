/* pt_server behaviour under hostile clients: slowloris, oversized bodies, connection floods. */
#include "pt/pt_server.h"
#include "unity.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pt_srv_t srv;
static atomic_bool stop;
static pthread_t thr;
static uint16_t port;
static atomic_int handled;
static atomic_int rejected_408;

static void handler(void *ctx, const pt_srv_request_t *req, pt_srv_response_t *resp)
{
    (void)ctx;
    static char body[256];
    const char *ua = NULL;
    size_t ual = 0;
    bool has_ua = pt_http_header(req->head, req->head_len, "x-test", &ua, &ual);
    int n = snprintf(body, sizeof(body), "%s %.*s body=%zu peer=%s hdr=%.*s", req->method,
                     (int)req->target_len, req->target, req->body_len, req->peer,
                     has_ua ? (int)ual : 0, has_ua ? ua : "");
    resp->status = 200;
    resp->content_type = "text/plain";
    resp->headers = "X-Extra: yes\r\n";
    resp->body = body;
    resp->body_len = (size_t)n;
    atomic_fetch_add(&handled, 1);
}

static void on_reject(void *ctx, int status, const char *peer)
{
    (void)ctx;
    (void)peer;
    if (status == 408) {
        atomic_fetch_add(&rejected_408, 1);
    }
}

static void *loop(void *arg)
{
    (void)arg;
    while (!atomic_load(&stop)) {
        pt_srv_poll(&srv, 20);
    }
    return NULL;
}

void setUp(void)
{
    static uint16_t next = 23000;
    port = next++;
    atomic_store(&stop, false);
    atomic_store(&handled, 0);
    atomic_store(&rejected_408, 0);
    pt_srv_config_t cfg = {.ports = {port, 0},
                           .bind_addr = "127.0.0.1",
                           .max_conns = 4,
                           .max_per_peer = 3,
                           .request_timeout_ms = 400,
                           .send_timeout_ms = 1000,
                           .handler = handler,
                           .on_reject = on_reject};
    TEST_ASSERT_EQUAL(PT_OK, pt_srv_open(&srv, &cfg));
    pthread_create(&thr, NULL, loop, NULL);
}

void tearDown(void)
{
    atomic_store(&stop, true);
    pthread_join(thr, NULL);
    pt_srv_close(&srv);
}

static int connect_from(const char *src)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (src != NULL) {
        struct sockaddr_in me = {.sin_family = AF_INET};
        inet_pton(AF_INET, src, &me.sin_addr);
        TEST_ASSERT_EQUAL(0, bind(fd, (struct sockaddr *)&me, sizeof(me)));
    }
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    TEST_ASSERT_EQUAL(0, connect(fd, (struct sockaddr *)&sa, sizeof(sa)));
    struct timeval tv = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static int connect_local(void)
{
    return connect_from(NULL);
}

/* Send a request and read the full response (until close). */
static size_t exchange_from(const char *src, const char *req, size_t len, char *out, size_t cap)
{
    int fd = connect_from(src);
    TEST_ASSERT_EQUAL((ssize_t)len, send(fd, req, len, 0));
    size_t have = 0;
    for (;;) {
        ssize_t n = recv(fd, out + have, cap - 1 - have, 0);
        if (n <= 0) {
            break;
        }
        have += (size_t)n;
    }
    out[have] = '\0';
    close(fd);
    return have;
}

static size_t exchange(const char *req, size_t len, char *out, size_t cap)
{
    return exchange_from(NULL, req, len, out, cap);
}

static void test_basic_request(void)
{
    char out[1024];
    const char *req = "POST /rec/abc HTTP/1.1\r\nHost: x\r\nX-Test: hello\r\n"
                      "Content-Length: 5\r\n\r\nhello";
    exchange(req, strlen(req), out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "HTTP/1.1 200 OK\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(out, "X-Extra: yes\r\n\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(out, "Connection: close"));
    TEST_ASSERT_NOT_NULL(strstr(out, "POST /rec/abc body=5 peer=127.0.0.1 hdr=hello"));
}

static void test_split_request(void)
{
    int fd = connect_local();
    const char *a = "GET /adv HT";
    const char *b = "TP/1.1\r\nHost: x\r\n\r\n";
    send(fd, a, strlen(a), 0);
    usleep(50000);
    send(fd, b, strlen(b), 0);
    char out[512];
    ssize_t n = recv(fd, out, sizeof(out) - 1, 0);
    TEST_ASSERT_TRUE(n > 0);
    out[n] = '\0';
    TEST_ASSERT_NOT_NULL(strstr(out, "200 OK"));
    close(fd);
}

static void test_slowloris_does_not_block_others(void)
{
    int slow = connect_local();
    send(slow, "GET /adv HTTP/1.1\r\n", 19, 0);
    /* While the slow client dribbles, a normal client is served promptly. */
    struct timespec t0;
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char out[512];
    exchange("GET /adv HTTP/1.1\r\n\r\n", 21, out, sizeof(out));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    TEST_ASSERT_NOT_NULL(strstr(out, "200 OK"));
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    TEST_ASSERT_TRUE(ms < 200);
    /* The slow client gets 408 after the request deadline. */
    send(slow, "X", 1, 0);
    char r[256];
    ssize_t n = recv(slow, r, sizeof(r) - 1, 0);
    TEST_ASSERT_TRUE(n > 0);
    r[n] = '\0';
    TEST_ASSERT_NOT_NULL(strstr(r, "408"));
    TEST_ASSERT_EQUAL(1, atomic_load(&rejected_408));
    close(slow);
}

static void test_body_too_large_and_bad_head(void)
{
    char out[512];
    const char *big = "POST /rec/a HTTP/1.1\r\nContent-Length: 99999\r\n\r\n";
    exchange(big, strlen(big), out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "413"));
    const char *bad = "GET /a b HTTP/1.1\r\n\r\n";
    exchange(bad, strlen(bad), out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "400"));
    const char *te = "POST /rec/a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    exchange(te, strlen(te), out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "501"));
    TEST_ASSERT_EQUAL(0, atomic_load(&handled));
}

static void test_flood_evicts_oldest_and_recovers(void)
{
    int fds[8];
    for (int i = 0; i < 8; i++) {
        fds[i] = connect_from("127.0.0.1"); /* idle connections from one peer */
        usleep(5000);
    }
    usleep(50000);
    TEST_ASSERT_EQUAL(3, pt_srv_active(&srv)); /* per-peer cap */
    char out[512];
    exchange_from("127.0.0.1", "GET /adv HTTP/1.1\r\n\r\n", 21, out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "200 OK")); /* same peer: refused */
    int other = connect_from("127.0.0.3");   /* fills the last slot */
    usleep(20000);
    TEST_ASSERT_EQUAL(4, pt_srv_active(&srv));
    exchange_from("127.0.0.2", "GET /adv HTTP/1.1\r\n\r\n", 21, out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "200 OK")); /* evicts the oldest connection */
    for (int i = 0; i < 8; i++) {
        close(fds[i]);
    }
    close(other);
    usleep(600000);
    TEST_ASSERT_EQUAL(0, pt_srv_active(&srv));
}

static void test_open_rejects_bad_config(void)
{
    pt_srv_t s2;
    pt_srv_config_t cfg = {.ports = {0, 0},
                           .max_conns = 1,
                           .max_per_peer = 1,
                           .request_timeout_ms = 1,
                           .handler = handler};
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_srv_open(&s2, &cfg));
    cfg.ports[0] = port; /* already bound by the running server */
    cfg.bind_addr = "127.0.0.1";
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_srv_open(&s2, &cfg));
    cfg.max_conns = PT_SRV_MAX_CONNS + 1;
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_srv_open(&s2, &cfg));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_basic_request);
    RUN_TEST(test_split_request);
    RUN_TEST(test_slowloris_does_not_block_others);
    RUN_TEST(test_body_too_large_and_bad_head);
    RUN_TEST(test_flood_evicts_oldest_and_recovers);
    RUN_TEST(test_open_rejects_bad_config);
    return UNITY_END();
}
