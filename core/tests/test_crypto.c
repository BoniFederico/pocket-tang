/* Crypto backend tests, cross-checked against keys and outputs produced by upstream tang 14 /
 * jose 13 (core/tests/fixtures/tang14). */
#include "pt/pt_b64url.h"
#include "pt/pt_crypto.h"
#include "pt/pt_jwk.h"
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

static void hex_digest(pt_hash_alg_t alg, const char *msg, const char *expect_hex)
{
    uint8_t out[64];
    pt_iovec_t iov = {msg, strlen(msg)};
    TEST_ASSERT_EQUAL(PT_OK, pt_hash(alg, &iov, 1, out));
    char hex[129];
    for (size_t i = 0; i < pt_hash_len(alg); i++) {
        static const char H[] = "0123456789abcdef";
        hex[2 * i] = H[out[i] >> 4];
        hex[2 * i + 1] = H[out[i] & 15];
    }
    hex[2 * pt_hash_len(alg)] = '\0';
    TEST_ASSERT_EQUAL_STRING(expect_hex, hex);
}

/* FIPS 180 "abc" test vectors. */
static void test_hash_vectors(void)
{
    hex_digest(PT_HASH_SHA1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    hex_digest(PT_HASH_SHA224, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    hex_digest(PT_HASH_SHA256, "abc",
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    hex_digest(PT_HASH_SHA384, "abc",
               "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
               "8086072ba1e7cc2358baeca134c825a7");
    hex_digest(PT_HASH_SHA512, "abc",
               "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

static void test_hash_scatter_gather(void)
{
    uint8_t a[64];
    uint8_t b[64];
    pt_iovec_t one = {"hello world", 11};
    pt_iovec_t parts[3] = {{"hello", 5}, {" ", 1}, {"world", 5}};
    TEST_ASSERT_EQUAL(PT_OK, pt_hash(PT_HASH_SHA512, &one, 1, a));
    TEST_ASSERT_EQUAL(PT_OK, pt_hash(PT_HASH_SHA512, parts, 3, b));
    TEST_ASSERT_EQUAL_MEMORY(a, b, 64);
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_hash((pt_hash_alg_t)99, &one, 1, a));
    TEST_ASSERT_EQUAL(0, pt_hash_len((pt_hash_alg_t)99));
}

/* The /rec result recorded from upstream tangd equals d_server * X_client. */
static void test_ecmr_matches_upstream(void)
{
    pt_jwk_t exc;
    pt_jwk_t req;
    pt_jwk_t rep;
    tu_load_jwk("tang14/exc.jwk", &exc);
    tu_load_jwk("tang14/rec_req.json", &req);
    tu_load_jwk("tang14/rec_rep.json", &rep);
    TEST_ASSERT_TRUE(exc.has_d);
    TEST_ASSERT_FALSE(req.has_d);
    pt_p521_point_t out;
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_ecmr(exc.d, &req.pub, &out));
    TEST_ASSERT_EQUAL_MEMORY(rep.pub.x, out.x, PT_P521_LEN);
    TEST_ASSERT_EQUAL_MEMORY(rep.pub.y, out.y, PT_P521_LEN);
    /* Blinding randomness does not change the result. */
    tu_use_test_rng(7);
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_ecmr(exc.d, &req.pub, &out));
    TEST_ASSERT_EQUAL_MEMORY(rep.pub.x, out.x, PT_P521_LEN);
    /* Without an RNG the operation fails closed. */
    pt_crypto_set_rng(NULL, NULL);
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_p521_ecmr(exc.d, &req.pub, &out));
    pt_jwk_wipe(&exc);
}

/* The upstream advertisement signature verifies with our ES512 implementation. */
static void test_verify_upstream_adv_signature(void)
{
    pt_jwk_t sig;
    tu_load_jwk("tang14/sig.jwk", &sig);
    size_t n = 0;
    const char *adv = tu_read_fixture("tang14/adv.json", &n);
    char adv_copy[2048];
    memcpy(adv_copy, adv, n + 1);
    char payload[1600];
    char prot[128];
    char signature[256];
    TEST_ASSERT_EQUAL(0, tu_json_str(adv_copy, n, "payload", payload, sizeof(payload)));
    TEST_ASSERT_EQUAL(0, tu_json_str(adv_copy, n, "protected", prot, sizeof(prot)));
    TEST_ASSERT_EQUAL(0, tu_json_str(adv_copy, n, "signature", signature, sizeof(signature)));
    uint8_t raw[PT_ES512_SIG_LEN];
    TEST_ASSERT_EQUAL(PT_OK,
                      pt_b64url_decode_exact(signature, strlen(signature), raw, sizeof(raw)));
    pt_iovec_t in[3] = {{prot, strlen(prot)}, {".", 1}, {payload, strlen(payload)}};
    TEST_ASSERT_EQUAL(PT_OK, pt_es512_verify(&sig.pub, in, 3, raw));
    raw[10] ^= 1;
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_es512_verify(&sig.pub, in, 3, raw));
    pt_jwk_wipe(&sig);
}

static void test_sign_verify_and_determinism(void)
{
    uint8_t d[PT_P521_LEN];
    pt_p521_point_t pub;
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_keygen(d, &pub));
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_point_check(&pub));
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_scalar_check(d));
    pt_p521_point_t pub2;
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_public(d, &pub2));
    TEST_ASSERT_EQUAL_MEMORY(&pub, &pub2, sizeof(pub));
    uint8_t s1[PT_ES512_SIG_LEN];
    uint8_t s2[PT_ES512_SIG_LEN];
    pt_iovec_t msg = {"message", 7};
    TEST_ASSERT_EQUAL(PT_OK, pt_es512_sign(d, &msg, 1, s1));
    TEST_ASSERT_EQUAL(PT_OK, pt_es512_sign(d, &msg, 1, s2));
    TEST_ASSERT_EQUAL_MEMORY(s1, s2, sizeof(s1)); /* RFC 6979 */
    TEST_ASSERT_EQUAL(PT_OK, pt_es512_verify(&pub, &msg, 1, s1));
    pt_iovec_t other = {"messagf", 7};
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_es512_verify(&pub, &other, 1, s1));
}

/* ECMR identity used by clevis: (d_s * (X + E)) - (e * S) == d_s * X   where S = d_s*G. */
static void test_mcCallum_relyea_identity(void)
{
    uint8_t ds[PT_P521_LEN];
    pt_p521_point_t S;
    uint8_t c[PT_P521_LEN];
    pt_p521_point_t C;
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_keygen(ds, &S));
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_keygen(c, &C));
    /* Provisioning: K = c * S. Recovery uses d_s * C with blinding; here we just check that the
     * scalar multiplication commutes: d_s * C == c * S. */
    pt_p521_point_t k1;
    pt_p521_point_t k2;
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_ecmr(ds, &C, &k1));
    TEST_ASSERT_EQUAL(PT_OK, pt_p521_ecmr(c, &S, &k2));
    TEST_ASSERT_EQUAL_MEMORY(&k1, &k2, sizeof(k1));
}

static void test_rejects_invalid_points_and_scalars(void)
{
    pt_jwk_t exc;
    tu_load_jwk("tang14/exc.jwk", &exc);
    pt_p521_point_t p = exc.pub;
    pt_p521_point_t out;
    p.y[65] ^= 1; /* off curve */
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_point_check(&p));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_ecmr(exc.d, &p, &out));
    memset(&p, 0, sizeof(p)); /* (0,0) is not on the curve */
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_point_check(&p));
    memset(&p, 0xFF, sizeof(p)); /* coordinates >= p */
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_point_check(&p));
    uint8_t zero[PT_P521_LEN] = {0};
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_scalar_check(zero));
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_ecmr(zero, &exc.pub, &out));
    uint8_t big[PT_P521_LEN];
    memset(big, 0xFF, sizeof(big)); /* > n */
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_p521_scalar_check(big));
    uint8_t sig[PT_ES512_SIG_LEN];
    pt_iovec_t msg = {"m", 1};
    TEST_ASSERT_EQUAL(PT_ERR_INVALID, pt_es512_sign(big, &msg, 1, sig));
    pt_jwk_wipe(&exc);
}

static void test_requires_rng(void)
{
    pt_crypto_set_rng(NULL, NULL);
    uint8_t d[PT_P521_LEN] = {1};
    pt_p521_point_t pub;
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_p521_keygen(d, &pub));
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_p521_public(d, &pub));
    uint8_t sig[PT_ES512_SIG_LEN];
    pt_iovec_t msg = {"m", 1};
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_es512_sign(d, &msg, 1, sig));
    TEST_ASSERT_EQUAL(PT_ERR_STATE, pt_crypto_random(d, sizeof(d)));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hash_vectors);
    RUN_TEST(test_hash_scatter_gather);
    RUN_TEST(test_ecmr_matches_upstream);
    RUN_TEST(test_verify_upstream_adv_signature);
    RUN_TEST(test_sign_verify_and_determinism);
    RUN_TEST(test_mcCallum_relyea_identity);
    RUN_TEST(test_rejects_invalid_points_and_scalars);
    RUN_TEST(test_requires_rng);
    return UNITY_END();
}
