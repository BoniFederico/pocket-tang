#include "pt/pt_b64url.h"
#include "unity.h"
#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

static void roundtrip(const uint8_t *in, size_t n, const char *expect)
{
    char enc[256];
    uint8_t dec[128];
    size_t enc_len = 0;
    size_t dec_len = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_encode(in, n, enc, sizeof(enc), &enc_len));
    TEST_ASSERT_EQUAL_STRING(expect, enc);
    TEST_ASSERT_EQUAL(strlen(expect), enc_len);
    TEST_ASSERT_EQUAL(PT_B64URL_ENC_LEN(n), enc_len);
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode(enc, enc_len, dec, sizeof(dec), &dec_len));
    TEST_ASSERT_EQUAL(n, dec_len);
    if (n) {
        TEST_ASSERT_EQUAL_MEMORY(in, dec, n);
    }
}

/* RFC 4648 test vectors, translated to the URL-safe alphabet without padding. */
static void test_rfc4648_vectors(void)
{
    roundtrip((const uint8_t *)"", 0, "");
    roundtrip((const uint8_t *)"f", 1, "Zg");
    roundtrip((const uint8_t *)"fo", 2, "Zm8");
    roundtrip((const uint8_t *)"foo", 3, "Zm9v");
    roundtrip((const uint8_t *)"foob", 4, "Zm9vYg");
    roundtrip((const uint8_t *)"fooba", 5, "Zm9vYmE");
    roundtrip((const uint8_t *)"foobar", 6, "Zm9vYmFy");
}

/* RFC 7515 Appendix C example. */
static void test_rfc7515_appendix_c(void)
{
    const uint8_t in[] = {3, 236, 255, 224, 193};
    roundtrip(in, sizeof(in), "A-z_4ME");
}

static void test_rejects_padding_and_std_alphabet(void)
{
    uint8_t out[16];
    size_t n;
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("Zg==", 4, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("A+z/4ME", 7, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("Zm 9v", 5, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("Z", 1, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("Zm9vY", 5, out, sizeof(out), &n));
}

static void test_rejects_noncanonical_trailing_bits(void)
{
    uint8_t out[16];
    size_t n;
    /* "Zh" decodes to 'f' with non-zero unused bits; "Zg" is the canonical form. */
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("Zh", 2, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode("Zm9", 3, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode("Zm8", 3, out, sizeof(out), &n));
}

static void test_capacity_checks(void)
{
    char enc[4];
    uint8_t out[2];
    size_t n;
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE,
                      pt_b64url_encode((const uint8_t *)"foo", 3, enc, sizeof(enc), &n));
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, pt_b64url_decode("Zm9v", 4, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_b64url_decode_exact("Zm9v", 4, out, 2));
    uint8_t out3[3];
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode_exact("Zm9v", 4, out3, 3));
}

static void test_all_bytes(void)
{
    uint8_t in[256];
    for (int i = 0; i < 256; i++) {
        in[i] = (uint8_t)i;
    }
    char enc[400];
    uint8_t dec[256];
    size_t el = 0;
    size_t dl = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_encode(in, sizeof(in), enc, sizeof(enc), &el));
    for (size_t i = 0; i < el; i++) {
        TEST_ASSERT_TRUE(pt_b64url_is_char(enc[i]));
    }
    TEST_ASSERT_FALSE(pt_b64url_is_char('='));
    TEST_ASSERT_FALSE(pt_b64url_is_char('+'));
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode(enc, el, dec, sizeof(dec), &dl));
    TEST_ASSERT_EQUAL(256, dl);
    TEST_ASSERT_EQUAL_MEMORY(in, dec, 256);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rfc4648_vectors);
    RUN_TEST(test_rfc7515_appendix_c);
    RUN_TEST(test_rejects_padding_and_std_alphabet);
    RUN_TEST(test_rejects_noncanonical_trailing_bits);
    RUN_TEST(test_capacity_checks);
    RUN_TEST(test_all_bytes);
    return UNITY_END();
}
