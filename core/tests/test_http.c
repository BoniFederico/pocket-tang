#include "pt/pt_http.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

static pt_http_req_t req;

static int parse(const char *s)
{
    return pt_http_parse_head(s, strlen(s), 2048, &req);
}

static void test_clevis_style_request(void)
{
    const char *s = "POST /rec/abc HTTP/1.1\r\nHost: tang.local\r\nUser-Agent: curl/8.5.0\r\n"
                    "Accept: */*\r\nContent-Type: application/jwk+json\r\n"
                    "Content-Length: 229\r\n\r\n{...";
    TEST_ASSERT_EQUAL(0, parse(s));
    TEST_ASSERT_EQUAL_STRING("POST", req.method);
    TEST_ASSERT_EQUAL(8, req.target_len);
    TEST_ASSERT_EQUAL_MEMORY("/rec/abc", req.target, 8);
    TEST_ASSERT_TRUE(req.has_length);
    TEST_ASSERT_EQUAL(229, req.content_length);
    TEST_ASSERT_EQUAL(strlen(s) - 4, req.head_len);
    TEST_ASSERT_TRUE(req.keep_alive);
    TEST_ASSERT_EQUAL(1, req.minor_version);
}

static void test_get_and_connection(void)
{
    TEST_ASSERT_EQUAL(0, parse("GET /adv HTTP/1.0\r\n\r\n"));
    TEST_ASSERT_FALSE(req.keep_alive);
    TEST_ASSERT_FALSE(req.has_length);
    TEST_ASSERT_EQUAL(0, parse("GET /adv HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n"));
    TEST_ASSERT_TRUE(req.keep_alive);
    TEST_ASSERT_EQUAL(0, parse("GET /adv HTTP/1.1\r\nconnection: foo, CLOSE\r\n\r\n"));
    TEST_ASSERT_FALSE(req.keep_alive);
}

static void test_incomplete_and_limits(void)
{
    TEST_ASSERT_EQUAL(PT_HTTP_NEED_MORE, parse("GET /adv HTTP/1.1\r\nHost: x\r\n"));
    TEST_ASSERT_EQUAL(PT_HTTP_NEED_MORE, parse(""));
    static char big[PT_HTTP_MAX_HEAD + 10];
    memset(big, 'a', sizeof(big) - 1);
    TEST_ASSERT_EQUAL(-431, parse(big));
    TEST_ASSERT_EQUAL(-413, parse("POST /rec/a HTTP/1.1\r\nContent-Length: 2049\r\n\r\n"));
    static char longt[700];
    strcpy(longt, "GET /");
    memset(longt + 5, 'a', 600);
    strcpy(longt + 605, " HTTP/1.1\r\n\r\n");
    TEST_ASSERT_EQUAL(-414, parse(longt));
    char many[2000] = "GET / HTTP/1.1\r\n";
    for (int i = 0; i < PT_HTTP_MAX_HEADERS + 1; i++) {
        strcat(many, "X-A: b\r\n");
    }
    strcat(many, "\r\n");
    TEST_ASSERT_EQUAL(-431, parse(many));
}

static void test_rejects_malformed(void)
{
    const char *bad[] = {
        "GET  /adv HTTP/1.1\r\n\r\n",
        "GET /adv  HTTP/1.1\r\n\r\n",
        "GET adv HTTP/1.1\r\n\r\n",
        "GET http://x/adv HTTP/1.1\r\n\r\n",
        "GET /adv HTTP/1.1\n\r\n\r\n",
        "GET /adv HTTP/2.0\r\n\r\n",
        "GET /adv FTP/1.1\r\n\r\n",
        "G(T /adv HTTP/1.1\r\n\r\n",
        "GET /a\x01v HTTP/1.1\r\n\r\n",
        "GET /adv HTTP/1.1\r\n folded: x\r\n\r\n",
        "GET /adv HTTP/1.1\r\nName : x\r\n\r\n",
        "GET /adv HTTP/1.1\r\nNoColon\r\n\r\n",
        "GET /adv HTTP/1.1\r\nX: a\x7f\r\n\r\n",
        "POST /rec/a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST /rec/a HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        "POST /rec/a HTTP/1.1\r\nContent-Length: 1 2\r\n\r\n",
        "POST /rec/a HTTP/1.1\r\nContent-Length: 9999999999\r\n\r\n",
        "POST /rec/a HTTP/1.1\r\nContent-Length:\r\n\r\n",
        "VERYLONGMETHOD /adv HTTP/1.1\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = parse(bad[i]);
        if (rc >= 0) {
            TEST_FAIL_MESSAGE(bad[i]);
        }
    }
    TEST_ASSERT_EQUAL(-505, parse("GET /adv HTTP/1.2\r\n\r\n"));
    TEST_ASSERT_EQUAL(-501, parse("POST /rec/a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"));
}

static void test_response_head(void)
{
    char out[256];
    size_t n = pt_http_write_head(out, sizeof(out), 200, "application/jose+json", 993, false);
    TEST_ASSERT_EQUAL_STRING("HTTP/1.1 200 OK\r\nContent-Type: application/jose+json\r\n"
                             "Content-Length: 993\r\nConnection: close\r\n\r\n",
                             out);
    TEST_ASSERT_EQUAL(strlen(out), n);
    n = pt_http_write_head(out, sizeof(out), 404, NULL, 0, true);
    TEST_ASSERT_EQUAL_STRING(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", out);
    TEST_ASSERT_EQUAL(0, pt_http_write_head(out, 10, 200, NULL, 0, false));
    TEST_ASSERT_EQUAL_STRING("Unknown", pt_http_reason(299));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_clevis_style_request);
    RUN_TEST(test_get_and_connection);
    RUN_TEST(test_incomplete_and_limits);
    RUN_TEST(test_rejects_malformed);
    RUN_TEST(test_response_head);
    return UNITY_END();
}
