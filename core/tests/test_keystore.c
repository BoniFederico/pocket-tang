#include "pt/pt_keystore.h"
#include "test_util.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    tu_use_test_rng(42);
}
void tearDown(void)
{
}

static pt_keystore_t ks;
static pt_keystore_t ks2;

static void kid_of(const pt_key_t *k, pt_hash_alg_t h, char *out)
{
    TEST_ASSERT_EQUAL(PT_OK, pt_jwk_thumbprint_b64(&k->pub, h, out, PT_THP_MAX));
}

static void test_ensure_creates_one_pair(void)
{
    pt_keystore_init(&ks);
    TEST_ASSERT_NULL(pt_keystore_active(&ks, PT_ALG_ES512));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_ensure(&ks));
    TEST_ASSERT_EQUAL(2, pt_keystore_count(&ks));
    TEST_ASSERT_NOT_NULL(pt_keystore_active(&ks, PT_ALG_ES512));
    TEST_ASSERT_NOT_NULL(pt_keystore_active(&ks, PT_ALG_ECMR));
    uint32_t gen = ks.generation;
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_ensure(&ks));
    TEST_ASSERT_EQUAL(2, pt_keystore_count(&ks));
    TEST_ASSERT_EQUAL(gen, ks.generation);
}

static void test_find_by_every_hash(void)
{
    pt_keystore_init(&ks);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_ensure(&ks));
    const pt_key_t *exc = pt_keystore_active(&ks, PT_ALG_ECMR);
    for (int h = 0; h < PT_HASH_COUNT; h++) {
        char kid[PT_THP_MAX];
        kid_of(exc, (pt_hash_alg_t)h, kid);
        TEST_ASSERT_EQUAL_PTR(exc, pt_keystore_find(&ks, kid, strlen(kid)));
    }
    TEST_ASSERT_NULL(pt_keystore_find(&ks, "AAAA", 4));
    TEST_ASSERT_NULL(pt_keystore_find(&ks, "", 0));
    TEST_ASSERT_NULL(pt_keystore_find(&ks, "!!!", 3));
    char longkid[200];
    memset(longkid, 'A', sizeof(longkid));
    TEST_ASSERT_NULL(pt_keystore_find(&ks, longkid, sizeof(longkid)));
}

static void test_rotation_semantics(void)
{
    pt_keystore_init(&ks);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_ensure(&ks));
    char old_exc[PT_THP_MAX];
    kid_of(pt_keystore_active(&ks, PT_ALG_ECMR), PT_HASH_SHA256, old_exc);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_rotate(&ks));
    TEST_ASSERT_EQUAL(4, pt_keystore_count(&ks));
    const pt_key_t *old = pt_keystore_find(&ks, old_exc, strlen(old_exc));
    TEST_ASSERT_NOT_NULL(old);
    TEST_ASSERT_TRUE(old->rotated);
    TEST_ASSERT_TRUE(old != pt_keystore_active(&ks, PT_ALG_ECMR));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_rotate(&ks));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_rotate(&ks));
    TEST_ASSERT_EQUAL(8, pt_keystore_count(&ks));
    TEST_ASSERT_EQUAL(PT_ERR_LIMIT, pt_keystore_rotate(&ks));
    TEST_ASSERT_EQUAL(8, pt_keystore_count(&ks));
    char act[PT_THP_MAX];
    kid_of(pt_keystore_active(&ks, PT_ALG_ECMR), PT_HASH_SHA1, act);
    TEST_ASSERT_EQUAL(PT_ERR_FORBIDDEN, pt_keystore_purge(&ks, act, strlen(act)));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_purge(&ks, old_exc, strlen(old_exc)));
    TEST_ASSERT_NULL(pt_keystore_find(&ks, old_exc, strlen(old_exc)));
    TEST_ASSERT_EQUAL(PT_ERR_NOTFOUND, pt_keystore_purge(&ks, old_exc, strlen(old_exc)));
    TEST_ASSERT_EQUAL(5, pt_keystore_purge_rotated(&ks));
    TEST_ASSERT_EQUAL(2, pt_keystore_count(&ks));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_rotate(&ks));
}

static void test_save_load_roundtrip_and_tamper(void)
{
    pt_keystore_init(&ks);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_ensure(&ks));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_rotate(&ks));
    static uint8_t blob[PT_KEYSTORE_BLOB_MAX];
    size_t len = 0;
    TEST_ASSERT_EQUAL(PT_ERR_NOSPACE, pt_keystore_save(&ks, blob, 10, &len));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_save(&ks, blob, sizeof(blob), &len));
    TEST_ASSERT_EQUAL(PT_KEYSTORE_BLOB_LEN(4), len);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_load(&ks2, blob, len));
    TEST_ASSERT_EQUAL(4, pt_keystore_count(&ks2));
    for (unsigned i = 0; i < 4; i++) {
        const pt_key_t *a = pt_keystore_at(&ks, i);
        const pt_key_t *b = pt_keystore_at(&ks2, i);
        TEST_ASSERT_EQUAL_MEMORY(a->d, b->d, PT_P521_LEN);
        TEST_ASSERT_EQUAL_MEMORY(&a->pub, &b->pub, sizeof(a->pub));
        TEST_ASSERT_EQUAL(a->alg, b->alg);
        TEST_ASSERT_EQUAL(a->rotated, b->rotated);
        TEST_ASSERT_EQUAL_MEMORY(a->thp, b->thp, sizeof(a->thp));
    }
    for (size_t i = 0; i < len; i += 7) {
        blob[i] ^= 0x10;
        TEST_ASSERT_TRUE(pt_keystore_load(&ks2, blob, len) != PT_OK);
        TEST_ASSERT_EQUAL(0, pt_keystore_count(&ks2));
        blob[i] ^= 0x10;
    }
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_keystore_load(&ks2, blob, len - 1));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_keystore_load(&ks2, NULL, 0));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_load(&ks2, blob, len));
}

static void test_import_upstream_keys(void)
{
    pt_jwk_t sig;
    pt_jwk_t exc;
    tu_load_jwk("tang14/sig.jwk", &sig);
    tu_load_jwk("tang14/exc.jwk", &exc);
    pt_keystore_init(&ks);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_import(&ks, &sig, false));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_import(&ks, &exc, false));
    TEST_ASSERT_EQUAL(PT_ERR_DUPLICATE, pt_keystore_import(&ks, &exc, false));
    TEST_ASSERT_NOT_NULL(pt_keystore_find(&ks, "BCcYRlKmK017L6ml2GIiQtXp05lrX1S-AQhqmiduonM", 43));
    TEST_ASSERT_NOT_NULL(pt_keystore_find(&ks, "rvs-e08wPU-KkuLUOmxbHG4mTvg", 27));
    pt_jwk_t pub_only = exc;
    pub_only.has_d = false;
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_keystore_import(&ks, &pub_only, true));
    pt_jwk_wipe(&sig);
    pt_jwk_wipe(&exc);
    pt_jwk_wipe(&pub_only);
    pt_keystore_wipe(&ks);
    TEST_ASSERT_EQUAL(0, pt_keystore_count(&ks));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ensure_creates_one_pair);
    RUN_TEST(test_find_by_every_hash);
    RUN_TEST(test_rotation_semantics);
    RUN_TEST(test_save_load_roundtrip_and_tamper);
    RUN_TEST(test_import_upstream_keys);
    return UNITY_END();
}
