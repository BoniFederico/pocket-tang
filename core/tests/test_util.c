#include "test_util.h"
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sys_rng(void *ctx, uint8_t *buf, size_t len)
{
    FILE *f = (FILE *)ctx;
    return fread(buf, 1, len, f) == len ? 0 : -1;
}

void tu_use_system_rng(void)
{
    static FILE *f;
    if (f == NULL) {
        f = fopen("/dev/urandom", "rb");
    }
    TEST_ASSERT_NOT_NULL(f);
    pt_crypto_set_rng(sys_rng, f);
}

static uint64_t g_state;

static int test_rng(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        /* splitmix64: deterministic, NOT cryptographically secure; tests only */
        uint64_t z = (g_state += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        buf[i] = (uint8_t)(z ^ (z >> 31));
    }
    return 0;
}

void tu_use_test_rng(unsigned seed)
{
    g_state = seed;
    pt_crypto_set_rng(test_rng, NULL);
}

const char *tu_read_fixture(const char *name, size_t *len)
{
    static char buf[8192];
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", PT_FIXTURE_DIR, name);
    FILE *f = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(f, path);
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    /* strip one trailing newline if present */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        n--;
    }
    buf[n] = '\0';
    if (len) {
        *len = n;
    }
    return buf;
}

void tu_load_jwk(const char *name, pt_jwk_t *out)
{
    size_t n = 0;
    const char *s = tu_read_fixture(name, &n);
    pt_json_tok_t toks[64];
    pt_json_doc_t doc;
    TEST_ASSERT_EQUAL(PT_OK, pt_json_parse(s, n, toks, 64, &doc));
    TEST_ASSERT_EQUAL(PT_OK, pt_jwk_parse(&doc, 0, true, out));
}

int tu_json_str(const char *json, size_t len, const char *member, char *out, size_t cap)
{
    pt_json_tok_t toks[128];
    pt_json_doc_t doc;
    if (pt_json_parse(json, len, toks, 128, &doc) != PT_OK) {
        return -1;
    }
    int t = pt_json_obj_get(&doc, 0, member);
    if (t < 0) {
        return -1;
    }
    return pt_json_str_get(&doc, t, out, cap, NULL) == PT_OK ? 0 : -1;
}
