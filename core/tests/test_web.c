#include "pt/pt_crypto.h"
#include "pt/pt_web.h"
#include "test_util.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    tu_use_system_rng();
}
void tearDown(void)
{
}

static pt_err_t get(const char *body, const char *name, char *out, size_t cap)
{
    return pt_form_get(body, strlen(body), name, out, cap, NULL);
}

static void test_form_parsing(void)
{
    char v[64];
    const char *b = "ssid=My+Home%20Wi-Fi&pass=p%40ss%26word%3D&empty=&flag&port=80";
    TEST_ASSERT_EQUAL(PT_OK, get(b, "ssid", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("My Home Wi-Fi", v);
    TEST_ASSERT_EQUAL(PT_OK, get(b, "pass", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("p@ss&word=", v);
    TEST_ASSERT_EQUAL(PT_OK, get(b, "empty", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("", v);
    TEST_ASSERT_EQUAL(PT_OK, get(b, "flag", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("", v);
    TEST_ASSERT_EQUAL(PT_OK, get(b, "port", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("80", v);
    TEST_ASSERT_EQUAL(PT_ERR_NOTFOUND, get(b, "host", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_NOTFOUND, get("", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_OK, get("a%3Db=1", "a=b", v, sizeof(v))); /* encoded key */
    TEST_ASSERT_EQUAL_STRING("1", v);
    TEST_ASSERT_EQUAL(PT_OK, get("x=%E2%82%AC", "x", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("\xE2\x82\xAC", v);
}

static void test_form_rejects(void)
{
    char v[8];
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, get("a=1&a=2", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, get("a=%4", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, get("a=%", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, get("a=%zz", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, get("a=%00", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, get("a=%0A", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, get("a=12345678", "a", v, sizeof(v)));
    TEST_ASSERT_EQUAL(PT_OK, get("a=1234567", "a", v, sizeof(v)));
    static char big[PT_FORM_MAX + 2];
    memset(big, 'a', sizeof(big) - 1);
    TEST_ASSERT_EQUAL(PT_ERR_LIMIT, get(big, "a", v, sizeof(v)));
}

static void test_html_escape(void)
{
    char out[64];
    TEST_ASSERT_EQUAL(PT_OK, pt_html_escape("<script>alert('x\"&')</script>", out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("&lt;script&gt;alert(&#39;x&quot;&amp;&#39;)&lt;/script&gt;", out);
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, pt_html_escape("<<<<", out, 10));
    TEST_ASSERT_EQUAL_STRING("", out);
    TEST_ASSERT_EQUAL(PT_OK, pt_html_escape("", out, 1));
}

/* RFC 7914 section 11 / widely published PBKDF2-HMAC-SHA256 vectors. */
static void test_pbkdf2_vectors(void)
{
    uint8_t out[64];
    static const uint8_t v1[32] = {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22,
                                   0x52, 0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc,
                                   0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b};
    TEST_ASSERT_EQUAL(PT_OK, pt_pbkdf2_sha256((const uint8_t *)"password", 8,
                                              (const uint8_t *)"salt", 4, 1, out, 32));
    TEST_ASSERT_EQUAL_MEMORY(v1, out, 32);
    static const uint8_t v2[32] = {0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d,
                                   0xb6, 0x84, 0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce,
                                   0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a};
    TEST_ASSERT_EQUAL(PT_OK, pt_pbkdf2_sha256((const uint8_t *)"password", 8,
                                              (const uint8_t *)"salt", 4, 4096, out, 32));
    TEST_ASSERT_EQUAL_MEMORY(v2, out, 32);
    /* RFC 7914: P="passwd", S="salt", c=1, dkLen=64 (first 8 bytes) */
    static const uint8_t v3[8] = {0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f};
    TEST_ASSERT_EQUAL(PT_OK, pt_pbkdf2_sha256((const uint8_t *)"passwd", 6, (const uint8_t *)"salt",
                                              4, 1, out, 64));
    TEST_ASSERT_EQUAL_MEMORY(v3, out, 8);
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_pbkdf2_sha256((const uint8_t *)"p", 1,
                                                       (const uint8_t *)"s", 1, 0, out, 32));
}

static void test_passwords(void)
{
    pt_pw_t v;
    TEST_ASSERT_FALSE(pt_pw_acceptable("short", 5));
    TEST_ASSERT_FALSE(pt_pw_acceptable("with\nnewline", 12));
    TEST_ASSERT_TRUE(pt_pw_acceptable("correct horse", 13));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_pw_set(&v, "short", 5, 10));
    TEST_ASSERT_EQUAL(PT_OK, pt_pw_set(&v, "correct horse", 13, 100));
    TEST_ASSERT_TRUE(pt_pw_check(&v, "correct horse", 13));
    TEST_ASSERT_FALSE(pt_pw_check(&v, "correct horsf", 13));
    TEST_ASSERT_FALSE(pt_pw_check(&v, "correct hors", 12));
    pt_pw_t v2;
    TEST_ASSERT_EQUAL(PT_OK, pt_pw_set(&v2, "correct horse", 13, 100));
    TEST_ASSERT_FALSE(memcmp(v.salt, v2.salt, sizeof(v.salt)) == 0); /* salted */
    TEST_ASSERT_FALSE(memcmp(v.hash, v2.hash, sizeof(v.hash)) == 0);
}

static void test_sessions(void)
{
    pt_session_t s;
    memset(&s, 0, sizeof(s));
    char cookie[PT_TOKEN_B64];
    char csrf[PT_TOKEN_B64];
    TEST_ASSERT_FALSE(pt_session_check_cookie(&s, "ptsid=AAAAAAAAAAAAAAAAAAAAAA", 0));
    TEST_ASSERT_EQUAL(PT_OK, pt_session_new(&s, 100, 600, cookie, csrf));
    TEST_ASSERT_EQUAL(22, strlen(cookie));
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "theme=dark; ptsid=%s; other=1", cookie);
    TEST_ASSERT_TRUE(pt_session_check_cookie(&s, hdr, 200));
    TEST_ASSERT_FALSE(pt_session_check_cookie(&s, hdr, 700)); /* expired */
    snprintf(hdr, sizeof(hdr), "ptsid=%s; ptsid=%s", cookie, cookie);
    TEST_ASSERT_FALSE(pt_session_check_cookie(&s, hdr, 200)); /* duplicate */
    snprintf(hdr, sizeof(hdr), "xptsid=%s", cookie);
    TEST_ASSERT_FALSE(pt_session_check_cookie(&s, hdr, 200));
    TEST_ASSERT_TRUE(pt_session_check_csrf(&s, csrf, strlen(csrf)));
    TEST_ASSERT_FALSE(pt_session_check_csrf(&s, cookie, strlen(cookie)));
    TEST_ASSERT_FALSE(pt_session_check_csrf(&s, csrf, strlen(csrf) - 1));
    char old[PT_TOKEN_B64];
    memcpy(old, cookie, sizeof(old));
    TEST_ASSERT_EQUAL(PT_OK, pt_session_new(&s, 100, 600, cookie, csrf)); /* replaces */
    snprintf(hdr, sizeof(hdr), "ptsid=%s", old);
    TEST_ASSERT_FALSE(pt_session_check_cookie(&s, hdr, 200));
    pt_session_end(&s);
    snprintf(hdr, sizeof(hdr), "ptsid=%s", cookie);
    TEST_ASSERT_FALSE(pt_session_check_cookie(&s, hdr, 200));
}

static void test_ratelimit(void)
{
    pt_ratelimit_t r = {0};
    TEST_ASSERT_TRUE(pt_ratelimit_allowed(&r, 0));
    pt_ratelimit_fail(&r, 10);
    pt_ratelimit_fail(&r, 10);
    TEST_ASSERT_TRUE(pt_ratelimit_allowed(&r, 10));
    pt_ratelimit_fail(&r, 10); /* third failure: 1 s */
    TEST_ASSERT_FALSE(pt_ratelimit_allowed(&r, 10));
    TEST_ASSERT_TRUE(pt_ratelimit_allowed(&r, 11));
    for (int i = 0; i < 20; i++) {
        pt_ratelimit_fail(&r, 100);
    }
    TEST_ASSERT_FALSE(pt_ratelimit_allowed(&r, 399));
    TEST_ASSERT_TRUE(pt_ratelimit_allowed(&r, 400)); /* capped at 300 s */
    pt_ratelimit_ok(&r);
    TEST_ASSERT_TRUE(pt_ratelimit_allowed(&r, 100));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_form_parsing);
    RUN_TEST(test_form_rejects);
    RUN_TEST(test_html_escape);
    RUN_TEST(test_pbkdf2_vectors);
    RUN_TEST(test_passwords);
    RUN_TEST(test_sessions);
    RUN_TEST(test_ratelimit);
    return UNITY_END();
}
