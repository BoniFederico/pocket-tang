#include "pt/pt_jwk.h"
#include "test_util.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

void setUp(void)
{
    tu_use_system_rng();
}
void tearDown(void)
{
}

static pt_json_tok_t toks[64];
static pt_json_doc_t doc;

static void parse(const char *s)
{
    TEST_ASSERT_EQUAL(PT_OK, pt_json_parse(s, strlen(s), toks, 64, &doc));
}

/* Thumbprints for every hash match `jose jwk thp` output recorded in thumbprints.txt. */
static void test_thumbprints_match_jose(void)
{
    static const char *const names[] = {"S1", "S224", "S256", "S384", "S512"};
    pt_jwk_t sig;
    pt_jwk_t exc;
    tu_load_jwk("tang14/sig.jwk", &sig);
    tu_load_jwk("tang14/exc.jwk", &exc);
    size_t n = 0;
    char txt[1024];
    memcpy(txt, tu_read_fixture("tang14/thumbprints.txt", &n), 1024);
    char *line = strtok(txt, "\n");
    int checked = 0;
    while (line != NULL) {
        char alg[8];
        char ts[100];
        char te[100];
        TEST_ASSERT_EQUAL(3, sscanf(line, "%7s sig=%99s exc=%99s", alg, ts, te));
        for (int h = 0; h < PT_HASH_COUNT; h++) {
            if (strcmp(alg, names[h]) == 0) {
                char out[PT_THP_MAX];
                TEST_ASSERT_EQUAL(
                    PT_OK, pt_jwk_thumbprint_b64(&sig.pub, (pt_hash_alg_t)h, out, sizeof(out)));
                TEST_ASSERT_EQUAL_STRING(ts, out);
                TEST_ASSERT_EQUAL(
                    PT_OK, pt_jwk_thumbprint_b64(&exc.pub, (pt_hash_alg_t)h, out, sizeof(out)));
                TEST_ASSERT_EQUAL_STRING(te, out);
                checked++;
            }
        }
        line = strtok(NULL, "\n");
    }
    TEST_ASSERT_EQUAL(5, checked);
    TEST_ASSERT_EQUAL(PT_ALG_ES512, sig.alg);
    TEST_ASSERT_EQUAL(PT_ALG_ECMR, exc.alg);
    pt_jwk_wipe(&sig);
    pt_jwk_wipe(&exc);
}

static void test_permits_matches_libjose(void)
{
    parse("{}");
    TEST_ASSERT_TRUE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, true, PT_OP_DERIVE_KEY));
    parse("{\"key_ops\":[\"deriveKey\"]}");
    TEST_ASSERT_TRUE(pt_jwk_permits(&doc, 0, true, PT_OP_DERIVE_KEY));
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_SIGN));
    parse("{\"key_ops\":[\"sign\",\"verify\"]}");
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    TEST_ASSERT_TRUE(pt_jwk_permits(&doc, 0, true, PT_OP_SIGN));
    parse("{\"use\":\"sig\"}");
    TEST_ASSERT_TRUE(pt_jwk_permits(&doc, 0, true, PT_OP_VERIFY));
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    parse("{\"use\":\"enc\"}"); /* upstream tangd answers 403 for this */
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    parse("{\"use\":\"enc\",\"key_ops\":[\"deriveKey\"]}");
    TEST_ASSERT_TRUE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    parse("{\"use\":1}");
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    parse("{\"key_ops\":\"deriveKey\"}");
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    parse("{\"key_ops\":[],\"key_ops\":[\"deriveKey\"]}");
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
    parse("[]");
    TEST_ASSERT_FALSE(pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY));
}

static const char *X =
    "AQb6w88D32yQFAbQwljaG3QA85jDehxg_dHUs_iDP5h1HPRKbezWe2pSCDrfeEAHKaFoatvbDqQ-tn770BQ3q6X7";
static const char *Y =
    "AYYVH4nRRwidDkHnvWsbRkU072NKSbDdQ5hiC_4IL5wMJj6BwueHQ7YpHXGQ4SssoNEh8equGR_fqzkXx3GIYKVW";

static pt_err_t try_parse(const char *kty, const char *crv, const char *x, const char *y,
                          const char *extra, bool allow_private)
{
    static char buf[1024];
    snprintf(buf, sizeof(buf), "{\"kty\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\",\"y\":\"%s\"%s}", kty,
             crv, x, y, extra);
    if (pt_json_parse(buf, strlen(buf), toks, 64, &doc) != PT_OK) {
        return PT_ERR_LIMIT;
    }
    pt_jwk_t k;
    pt_err_t err = pt_jwk_parse(&doc, 0, allow_private, &k);
    pt_jwk_wipe(&k);
    return err;
}

static void test_parse_validation(void)
{
    TEST_ASSERT_EQUAL(PT_OK, try_parse("EC", "P-521", X, Y, "", false));
    TEST_ASSERT_EQUAL(PT_OK, try_parse("EC", "P-521", X, Y, ",\"alg\":\"ECMR\"", false));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("RSA", "P-521", X, Y, "", false));
    TEST_ASSERT_EQUAL(PT_ERR_UNSUPPORTED, try_parse("EC", "P-256", X, Y, "", false));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", "AQ", Y, "", false));
    char xl[100];
    snprintf(xl, sizeof(xl), "%sA", X);
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", xl, Y, "", false));
    char yb[100];
    snprintf(yb, sizeof(yb), "%s", Y);
    yb[10] = yb[10] == 'A' ? 'B' : 'A';
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", X, yb, "", false));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", X, Y, ",\"x\":\"AA\"", false));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", X, Y, ",\"alg\":5", false));
    TEST_ASSERT_EQUAL(PT_ERR_FORBIDDEN, try_parse("EC", "P-521", X, Y, ",\"d\":\"AA\"", false));
    /* a private scalar that does not belong to the public point */
    size_t n = 0;
    const char *excs = tu_read_fixture("tang14/exc.jwk", &n);
    char d_b64[100];
    TEST_ASSERT_EQUAL(0, tu_json_str(excs, n, "d", d_b64, sizeof(d_b64)));
    char extra[200];
    snprintf(extra, sizeof(extra), ",\"d\":\"%s\"", d_b64);
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", X, Y, extra, true));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, try_parse("EC", "P-521", "\\u0041Q", Y, "", false));
}

static void test_write_public_roundtrip(void)
{
    pt_jwk_t sig;
    tu_load_jwk("tang14/sig.jwk", &sig);
    char buf[512];
    pt_jw_t w;
    pt_jw_init(&w, buf, sizeof(buf));
    pt_jwk_write_public(&w, &sig.pub, PT_ALG_ES512, 1u << PT_OP_VERIFY);
    size_t n = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_jw_finish(&w, &n));
    const char *prefix = "{\"alg\":\"ES512\",\"crv\":\"P-521\",\"key_ops\":[\"verify\"],"
                         "\"kty\":\"EC\",\"x\":\"AHN0YPzPYRQ6zn";
    TEST_ASSERT_EQUAL_STRING_LEN(prefix, buf, strlen(prefix));
    pt_json_tok_t t2[32];
    pt_json_doc_t d2;
    TEST_ASSERT_EQUAL(PT_OK, pt_json_parse(buf, n, t2, 32, &d2));
    pt_jwk_t back;
    TEST_ASSERT_EQUAL(PT_OK, pt_jwk_parse(&d2, 0, false, &back));
    TEST_ASSERT_EQUAL_MEMORY(&sig.pub, &back.pub, sizeof(sig.pub));
    TEST_ASSERT_EQUAL(PT_ALG_ES512, back.alg);
    pt_jwk_wipe(&sig);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_thumbprints_match_jose);
    RUN_TEST(test_permits_matches_libjose);
    RUN_TEST(test_parse_validation);
    RUN_TEST(test_write_public_roundtrip);
    return UNITY_END();
}
