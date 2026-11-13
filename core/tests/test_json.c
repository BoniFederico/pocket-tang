#include "pt/pt_json.h"
#include "unity.h"
#include <stdio.h>
#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

static pt_json_tok_t toks[64];
static pt_json_doc_t doc;

static pt_err_t parse(const char *s)
{
    return pt_json_parse(s, strlen(s), toks, 64, &doc);
}

static void test_parse_jwk_like_object(void)
{
    const char *s = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"key_ops\":[\"deriveKey\"],"
                    "\"x\":\"AQ\",\"y\":\"Ag\",\"n\":12,\"b\":true,\"z\":null,\"o\":{}}";
    TEST_ASSERT_EQUAL(PT_OK, parse(s));
    TEST_ASSERT_EQUAL(PT_JSON_OBJECT, pt_json_type(&doc, 0));
    TEST_ASSERT_EQUAL(9, toks[0].size);
    int kty = pt_json_obj_get(&doc, 0, "kty");
    TEST_ASSERT_TRUE(kty > 0);
    TEST_ASSERT_TRUE(pt_json_str_eq(&doc, kty, "EC"));
    TEST_ASSERT_FALSE(pt_json_str_eq(&doc, kty, "EC2"));
    int ops = pt_json_obj_get(&doc, 0, "key_ops");
    TEST_ASSERT_EQUAL(PT_JSON_ARRAY, pt_json_type(&doc, ops));
    TEST_ASSERT_TRUE(pt_json_arr_has_str(&doc, ops, "deriveKey"));
    TEST_ASSERT_FALSE(pt_json_arr_has_str(&doc, ops, "sign"));
    int y = pt_json_obj_get(&doc, 0, "y");
    char buf[8];
    size_t n = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_json_str_get(&doc, y, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_STRING("Ag", buf);
    TEST_ASSERT_EQUAL(2, n);
    TEST_ASSERT_EQUAL(-(int)PT_ERR_NOTFOUND, pt_json_obj_get(&doc, 0, "d"));
    int o = pt_json_obj_get(&doc, 0, "o");
    TEST_ASSERT_EQUAL(PT_JSON_OBJECT, pt_json_type(&doc, o));
    TEST_ASSERT_EQUAL(0, toks[o].size);
    TEST_ASSERT_EQUAL(doc.count, pt_json_skip(&doc, 0));
}

static void test_nested_skip_and_array_index(void)
{
    const char *s = "{\"a\":[{\"x\":[1,2,[3]]},\"s\",{\"k\":{\"q\":null}}],\"b\":\"v\"}";
    TEST_ASSERT_EQUAL(PT_OK, parse(s));
    int a = pt_json_obj_get(&doc, 0, "a");
    TEST_ASSERT_EQUAL(3, toks[a].size);
    int e1 = pt_json_arr_get(&doc, a, 1);
    TEST_ASSERT_TRUE(pt_json_str_eq(&doc, e1, "s"));
    int e2 = pt_json_arr_get(&doc, a, 2);
    int k = pt_json_obj_get(&doc, e2, "k");
    int q = pt_json_obj_get(&doc, k, "q");
    TEST_ASSERT_EQUAL(PT_JSON_PRIMITIVE, pt_json_type(&doc, q));
    TEST_ASSERT_EQUAL(-(int)PT_ERR_NOTFOUND, pt_json_arr_get(&doc, a, 3));
    int b = pt_json_obj_get(&doc, 0, "b");
    TEST_ASSERT_TRUE(pt_json_str_eq(&doc, b, "v"));
}

static void test_duplicate_key_is_error(void)
{
    TEST_ASSERT_EQUAL(PT_OK, parse("{\"kty\":\"EC\",\"x\":1,\"kty\":\"RSA\"}"));
    TEST_ASSERT_EQUAL(-(int)PT_ERR_DUPLICATE, pt_json_obj_get(&doc, 0, "kty"));
    TEST_ASSERT_TRUE(pt_json_obj_get(&doc, 0, "x") > 0);
}

static void test_escapes(void)
{
    const char *s = "{\"k\\u0074y\":\"a\\\"b\\\\c\\/d\\n\\u00e9\\ud83d\\ude00\"}";
    TEST_ASSERT_EQUAL(PT_OK, parse(s));
    int v = pt_json_obj_get(&doc, 0, "kty"); /* escaped key still matches */
    TEST_ASSERT_TRUE(v > 0);
    char buf[64];
    size_t n = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_json_str_get(&doc, v, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_STRING("a\"b\\c/d\n\xC3\xA9\xF0\x9F\x98\x80", buf);
    /* lone surrogates are rejected at decode time */
    TEST_ASSERT_EQUAL(PT_OK, parse("[\"\\ud83d\"]"));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_json_str_get(&doc, 1, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL(PT_OK, parse("[\"\\ude00\"]"));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_json_str_get(&doc, 1, buf, sizeof(buf), &n));
    /* capacity */
    TEST_ASSERT_EQUAL(PT_OK, parse("[\"abcdef\"]"));
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, pt_json_str_get(&doc, 1, buf, 6, &n));
    TEST_ASSERT_EQUAL(PT_OK, pt_json_str_get(&doc, 1, buf, 7, &n));
}

static void test_rejects_invalid_syntax(void)
{
    const char *bad[] = {
        "",
        " ",
        "{",
        "}",
        "{\"a\":1,}",
        "[1,]",
        "[,1]",
        "{\"a\" 1}",
        "{a:1}",
        "{'a':1}",
        "{\"a\":1}x",
        "{\"a\":1} {}",
        "[01]",
        "[1.]",
        "[.5]",
        "[1e]",
        "[+1]",
        "[-]",
        "[tru]",
        "[truee]",
        "[True]",
        "[NaN]",
        "[\"a\tb\"]",
        "[\"\\x41\"]",
        "[\"\\u12\"]",
        "[\"\\u12G4\"]",
        "[\"abc]",
        "[\"\xC0\xAF\"]",         /* overlong UTF-8 */
        "[\"\xED\xA0\x80\"]",     /* UTF-16 surrogate encoded in UTF-8 */
        "[\"\xF4\x90\x80\x80\"]", /* > U+10FFFF */
        "[\"\xFF\"]",
        "[1 2]",
        "{\"a\":1 \"b\":2}",
        "[1}",
        "{\"a\":1]",
        "\"abc\"\"def\"",
        "/* c */ {}",
        "{\"a\":1}\x00",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        size_t len = strlen(bad[i]);
        if (i == sizeof(bad) / sizeof(bad[0]) - 1) {
            len += 1; /* include the embedded NUL */
        }
        pt_err_t err = pt_json_parse(bad[i], len, toks, 64, &doc);
        if (err != PT_ERR_INVALID) {
            printf("case %zu: %s -> %d\n", i, bad[i], (int)err);
        }
        TEST_ASSERT_EQUAL(PT_ERR_INVALID, err);
    }
}

static void test_accepts_valid_forms(void)
{
    const char *good[] = {
        "{}",
        "[]",
        "0",
        "-0",
        "1.5e+10",
        "\"\"",
        "true",
        "false",
        "null",
        " \r\n\t{ } ",
        "[1,-2,3.25,4e5,5E-1,0.0]",
        "{\"\":\"\"}",
        "[\"\\u0000\"]",
        "[\"\xE2\x82\xAC\"]", /* euro sign */
        "[[[[[[[[]]]]]]]]",   /* depth 8 */
    };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        pt_err_t err = parse(good[i]);
        if (err != PT_OK) {
            printf("case %zu: %s -> %d\n", i, good[i], (int)err);
        }
        TEST_ASSERT_EQUAL(PT_OK, err);
    }
}

static void test_limits(void)
{
    TEST_ASSERT_EQUAL(PT_ERR_LIMIT, parse("[[[[[[[[[]]]]]]]]]")); /* depth 9 */
    TEST_ASSERT_EQUAL(PT_ERR_LIMIT, parse("{\"a\":[[[[[[[[]]]]]]]]}"));
    /* token capacity */
    pt_json_tok_t small[3];
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, pt_json_parse("[1,2,3]", 7, small, 3, &doc));
    TEST_ASSERT_EQUAL(PT_OK, pt_json_parse("[1,2]", 5, small, 3, &doc));
    /* input size */
    static char big[PT_JSON_MAX_INPUT + 2];
    memset(big, ' ', sizeof(big));
    TEST_ASSERT_EQUAL(PT_ERR_LIMIT, pt_json_parse(big, sizeof(big), toks, 64, &doc));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_json_parse(NULL, 0, toks, 64, &doc));
}

static void test_writer_basic(void)
{
    char buf[256];
    pt_jw_t w;
    pt_jw_init(&w, buf, sizeof(buf));
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "alg");
    pt_jw_str(&w, "ES512");
    pt_jw_key(&w, "ops");
    pt_jw_arr_begin(&w);
    pt_jw_str(&w, "sign");
    pt_jw_str(&w, "ve\"r\\i\nfy");
    pt_jw_arr_end(&w);
    pt_jw_key(&w, "n");
    pt_jw_uint(&w, 4294967295u);
    pt_jw_key(&w, "z");
    pt_jw_uint(&w, 0);
    pt_jw_key(&w, "b");
    pt_jw_bool(&w, true);
    pt_jw_key(&w, "nul");
    pt_jw_null(&w);
    pt_jw_key(&w, "raw");
    pt_jw_raw(&w, "{\"a\":[]}", 8);
    pt_jw_key(&w, "x");
    pt_jw_b64url(&w, (const uint8_t *)"foob", 4);
    pt_jw_key(&w, "e");
    pt_jw_obj_begin(&w);
    pt_jw_obj_end(&w);
    pt_jw_obj_end(&w);
    size_t n = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_jw_finish(&w, &n));
    TEST_ASSERT_EQUAL_STRING("{\"alg\":\"ES512\",\"ops\":[\"sign\",\"ve\\\"r\\\\i\\nfy\"],"
                             "\"n\":4294967295,\"z\":0,\"b\":true,\"nul\":null,"
                             "\"raw\":{\"a\":[]},\"x\":\"Zm9vYg\",\"e\":{}}",
                             buf);
    TEST_ASSERT_EQUAL(strlen(buf), n);
    /* the output must parse back */
    TEST_ASSERT_EQUAL(PT_OK, parse(buf));
}

static void test_writer_errors(void)
{
    char buf[16];
    pt_jw_t w;
    pt_jw_init(&w, buf, sizeof(buf));
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "averyveryverylongkey");
    pt_jw_str(&w, "v");
    pt_jw_obj_end(&w);
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, pt_jw_finish(&w, NULL));

    char buf2[64];
    pt_jw_init(&w, buf2, sizeof(buf2));
    pt_jw_obj_begin(&w);
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_jw_finish(&w, NULL)); /* unbalanced */

    pt_jw_init(&w, buf2, sizeof(buf2));
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "a");
    pt_jw_obj_end(&w); /* key without value */
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_jw_finish(&w, NULL));

    pt_jw_init(&w, buf2, sizeof(buf2));
    pt_jw_str(&w, "a");
    pt_jw_str(&w, "b"); /* two root values */
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_jw_finish(&w, NULL));

    pt_jw_init(&w, buf2, sizeof(buf2));
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_jw_finish(&w, NULL)); /* nothing written */

    pt_jw_init(&w, buf2, sizeof(buf2));
    pt_jw_key(&w, "a"); /* key at root */
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_jw_finish(&w, NULL));

    pt_jw_init(&w, buf2, sizeof(buf2));
    for (int i = 0; i < PT_JSON_MAX_DEPTH + 1; i++) {
        pt_jw_arr_begin(&w);
    }
    TEST_ASSERT_EQUAL(PT_ERR_LIMIT, pt_jw_finish(&w, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_jwk_like_object);
    RUN_TEST(test_nested_skip_and_array_index);
    RUN_TEST(test_duplicate_key_is_error);
    RUN_TEST(test_escapes);
    RUN_TEST(test_rejects_invalid_syntax);
    RUN_TEST(test_accepts_valid_forms);
    RUN_TEST(test_limits);
    RUN_TEST(test_writer_basic);
    RUN_TEST(test_writer_errors);
    return UNITY_END();
}
