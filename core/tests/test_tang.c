/* Protocol engine tests. Expected status codes are those observed from upstream tangd 14 for
 * the same requests (see docs/design/protocol-reference.md). */
#include "pt/pt_b64url.h"
#include "pt/pt_tang.h"
#include "test_util.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

static pt_tang_t tang;
static char out[PT_TANG_RESP_MAX];
static pt_tang_resp_t resp;
static int ev_ok;
static int ev_denied;
static int ev_adv;

static const char *KID_SIG = "7glF6LXy0S-ycToSk9eMsot2-O6vugtyPQ5y7Ekbrw8";
static const char *KID_SIG_S1 = "rvs-e08wPU-KkuLUOmxbHG4mTvg";
static const char *KID_EXC = "BCcYRlKmK017L6ml2GIiQtXp05lrX1S-AQhqmiduonM";
static const char *KID_EXC_S1 = "heCfiLiCixtMC56xV7M1dml9fLk";

static void on_event(void *ctx, pt_tang_event_t ev, int status, const char *kid)
{
    (void)ctx;
    (void)status;
    (void)kid;
    ev_ok += ev == PT_EV_REC_OK;
    ev_denied += ev == PT_EV_REC_DENIED;
    ev_adv += ev == PT_EV_ADV;
}

void setUp(void)
{
    tu_use_system_rng();
    pt_tang_init(&tang);
    pt_jwk_t sig;
    pt_jwk_t exc;
    tu_load_jwk("tang14/sig.jwk", &sig);
    tu_load_jwk("tang14/exc.jwk", &exc);
    /* Same order as the upstream key directory listing: exchange key first. */
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_import(pt_tang_keystore(&tang), &exc, false));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_import(pt_tang_keystore(&tang), &sig, false));
    pt_jwk_wipe(&sig);
    pt_jwk_wipe(&exc);
    pt_tang_set_event_cb(&tang, on_event, NULL);
    ev_ok = ev_denied = ev_adv = 0;
}

void tearDown(void)
{
    pt_tang_wipe(&tang);
}

static int request(const char *method, const char *path, const char *body)
{
    pt_tang_req_t req;
    pt_tang_route(method, path, strlen(path), &req);
    pt_tang_handle(&tang, &req, (const uint8_t *)body, body ? strlen(body) : 0, out, sizeof(out),
                   &resp);
    return resp.status;
}

static void test_routing_matches_upstream(void)
{
    char p[256];
    TEST_ASSERT_EQUAL(200, request("GET", "/adv", NULL));
    TEST_ASSERT_EQUAL_STRING("application/jose+json", resp.content_type);
    TEST_ASSERT_EQUAL(200, request("GET", "/adv/", NULL));
    TEST_ASSERT_EQUAL(200, request("GET", "//adv//", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "/adv?x=1", NULL));
    TEST_ASSERT_EQUAL(405, request("POST", "/adv", NULL));
    TEST_ASSERT_EQUAL(405, request("HEAD", "/adv", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "/foo", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "adv", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "/advx", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "/adv/AAAA", NULL));
    TEST_ASSERT_EQUAL(404, request("GET", "/adv/a.b", NULL));
    snprintf(p, sizeof(p), "/adv/%s", KID_EXC);
    TEST_ASSERT_EQUAL(404, request("GET", p, NULL)); /* exchange keys do not sign */
    snprintf(p, sizeof(p), "/rec/%s", KID_EXC);
    TEST_ASSERT_EQUAL(405, request("GET", p, NULL));
    TEST_ASSERT_EQUAL(404, request("POST", "/rec", NULL));
    TEST_ASSERT_EQUAL(404, request("POST", "/rec/", NULL));
    TEST_ASSERT_EQUAL(200, request("GET", "/version", NULL));
    TEST_ASSERT_EQUAL_STRING("application/json", resp.content_type);
    TEST_ASSERT_NOT_NULL(strstr(out, "\"name\":\"pocket-tang\""));
    char longp[300];
    memset(longp, 'A', sizeof(longp));
    memcpy(longp, "/adv/", 5);
    longp[sizeof(longp) - 1] = '\0';
    TEST_ASSERT_EQUAL(404, request("GET", longp, NULL));
}

/* Verify every signature of a JWS (flattened or general) with the given public key list. */
static int count_valid_signatures(const char *jws, const pt_p521_point_t *pub)
{
    pt_json_tok_t toks[64];
    pt_json_doc_t doc;
    TEST_ASSERT_EQUAL(PT_OK, pt_json_parse(jws, strlen(jws), toks, 64, &doc));
    char payload[PT_TANG_ADV_PAYLOAD_MAX];
    TEST_ASSERT_EQUAL(PT_OK, pt_json_str_get(&doc, pt_json_obj_get(&doc, 0, "payload"), payload,
                                             sizeof(payload), NULL));
    int sigs = pt_json_obj_get(&doc, 0, "signatures");
    int n = sigs >= 0 ? doc.toks[sigs].size : 1;
    int valid = 0;
    for (int i = 0; i < n; i++) {
        int obj = sigs >= 0 ? pt_json_arr_get(&doc, sigs, (unsigned)i) : 0;
        char prot[128];
        char sig[256];
        TEST_ASSERT_EQUAL(PT_OK, pt_json_str_get(&doc, pt_json_obj_get(&doc, obj, "protected"),
                                                 prot, sizeof(prot), NULL));
        TEST_ASSERT_EQUAL_STRING("eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9", prot);
        TEST_ASSERT_EQUAL(PT_OK, pt_json_str_get(&doc, pt_json_obj_get(&doc, obj, "signature"), sig,
                                                 sizeof(sig), NULL));
        uint8_t raw[PT_ES512_SIG_LEN];
        TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode_exact(sig, strlen(sig), raw, sizeof(raw)));
        pt_iovec_t in[3] = {{prot, strlen(prot)}, {".", 1}, {payload, strlen(payload)}};
        valid += pt_es512_verify(pub, in, 3, raw) == PT_OK;
    }
    return valid;
}

static void test_adv_payload_equals_upstream(void)
{
    TEST_ASSERT_EQUAL(200, request("GET", "/adv", NULL));
    char ours[PT_TANG_ADV_PAYLOAD_MAX];
    char theirs[PT_TANG_ADV_PAYLOAD_MAX];
    TEST_ASSERT_EQUAL(0, tu_json_str(out, resp.body_len, "payload", ours, sizeof(ours)));
    size_t n = 0;
    const char *adv = tu_read_fixture("tang14/adv.json", &n);
    TEST_ASSERT_EQUAL(0, tu_json_str(adv, n, "payload", theirs, sizeof(theirs)));
    /* Upstream serialises with ", " and ": " separators; compare the decoded JSON after removing
     * that whitespace (none of the values contains spaces). */
    uint8_t a[1200];
    uint8_t b[1200];
    size_t al = 0;
    size_t bl = 0;
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode(ours, strlen(ours), a, sizeof(a), &al));
    TEST_ASSERT_EQUAL(PT_OK, pt_b64url_decode(theirs, strlen(theirs), b, sizeof(b), &bl));
    size_t j = 0;
    for (size_t i = 0; i < bl; i++) {
        if (b[i] != ' ') {
            b[j++] = b[i];
        }
    }
    TEST_ASSERT_EQUAL(j, al);
    TEST_ASSERT_EQUAL_MEMORY(b, a, al);
    /* flattened serialisation with exactly one valid signature */
    TEST_ASSERT_NULL(strstr(out, "\"signatures\""));
    pt_jwk_t sig;
    tu_load_jwk("tang14/sig.jwk", &sig);
    TEST_ASSERT_EQUAL(1, count_valid_signatures(out, &sig.pub));
    TEST_ASSERT_EQUAL(1, ev_adv);
    pt_jwk_wipe(&sig);
}

static void test_adv_kid_signed_twice_like_upstream(void)
{
    char p[128];
    pt_jwk_t sig;
    tu_load_jwk("tang14/sig.jwk", &sig);
    snprintf(p, sizeof(p), "/adv/%s", KID_SIG);
    TEST_ASSERT_EQUAL(200, request("GET", p, NULL));
    TEST_ASSERT_NOT_NULL(strstr(out, "\"signatures\""));
    TEST_ASSERT_EQUAL(2, count_valid_signatures(out, &sig.pub));
    snprintf(p, sizeof(p), "/adv/%s", KID_SIG_S1);
    TEST_ASSERT_EQUAL(200, request("GET", p, NULL));
    pt_jwk_wipe(&sig);
}

static void test_adv_after_rotation(void)
{
    char p[128];
    pt_jwk_t oldsig;
    tu_load_jwk("tang14/sig.jwk", &oldsig);
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_rotate(pt_tang_keystore(&tang)));
    TEST_ASSERT_EQUAL(200, request("GET", "/adv", NULL));
    /* old signing key no longer signs /adv and the old keys are not advertised */
    TEST_ASSERT_EQUAL(0, count_valid_signatures(out, &oldsig.pub));
    char payload[PT_TANG_ADV_PAYLOAD_MAX];
    uint8_t json[1200];
    size_t jl = 0;
    TEST_ASSERT_EQUAL(0, tu_json_str(out, resp.body_len, "payload", payload, sizeof(payload)));
    TEST_ASSERT_EQUAL(PT_OK,
                      pt_b64url_decode(payload, strlen(payload), json, sizeof(json) - 1, &jl));
    json[jl] = '\0';
    TEST_ASSERT_NULL(strstr((const char *)json, "AHN0YPzPYRQ6zn"));
    /* the rotated signing key is still accepted as /adv/{kid} and adds its signature */
    snprintf(p, sizeof(p), "/adv/%s", KID_SIG);
    TEST_ASSERT_EQUAL(200, request("GET", p, NULL));
    TEST_ASSERT_EQUAL(1, count_valid_signatures(out, &oldsig.pub));
    pt_jwk_wipe(&oldsig);
}

static const char *rec_body(void)
{
    return tu_read_fixture("tang14/rec_req.json", NULL);
}

static void test_rec_byte_exact_with_upstream(void)
{
    char p[128];
    char body[512];
    snprintf(body, sizeof(body), "%s", rec_body());
    tang.include_tang_pub = false;
    snprintf(p, sizeof(p), "/rec/%s", KID_EXC);
    TEST_ASSERT_EQUAL(200, request("POST", p, body));
    TEST_ASSERT_EQUAL_STRING("application/jwk+json", resp.content_type);
    TEST_ASSERT_EQUAL_STRING(tu_read_fixture("tang14/rec_rep.json", NULL), out);
    TEST_ASSERT_EQUAL(strlen(out), resp.body_len);
    snprintf(p, sizeof(p), "/rec/%s", KID_EXC_S1);
    TEST_ASSERT_EQUAL(200, request("POST", p, body));
    TEST_ASSERT_EQUAL(2, ev_ok);
}

static void test_rec_with_tang_pub(void)
{
    char p[128];
    char body[512];
    snprintf(body, sizeof(body), "%s", rec_body());
    snprintf(p, sizeof(p), "/rec/%s", KID_EXC);
    TEST_ASSERT_EQUAL(200, request("POST", p, body));
    TEST_ASSERT_NOT_NULL(strstr(out, "\"tang_pub\":{\"alg\":\"ECMR\",\"crv\":\"P-521\","
                                     "\"key_ops\":[\"deriveKey\"],\"kty\":\"EC\",\"x\":\"AP7Ra9"));
    TEST_ASSERT_NULL(strstr(out, "\"d\""));
    /* the reply still carries the same x/y as upstream */
    char x[100];
    TEST_ASSERT_EQUAL(0, tu_json_str(out, resp.body_len, "x", x, sizeof(x)));
    TEST_ASSERT_NOT_NULL(strstr(tu_read_fixture("tang14/rec_rep.json", NULL), x));
}

/* Replace the first occurrence of @p from with @p to. */
static const char *subst(const char *s, const char *from, const char *to)
{
    static char buf[1024];
    const char *at = strstr(s, from);
    TEST_ASSERT_NOT_NULL(at);
    snprintf(buf, sizeof(buf), "%.*s%s%s", (int)(at - s), s, to, at + strlen(from));
    return buf;
}

static void test_rec_status_matrix_matches_upstream(void)
{
    char ok[512];
    char p_exc[128];
    char p_sig[128];
    snprintf(ok, sizeof(ok), "%s", rec_body());
    snprintf(p_exc, sizeof(p_exc), "/rec/%s", KID_EXC);
    snprintf(p_sig, sizeof(p_sig), "/rec/%s", KID_SIG);
    TEST_ASSERT_EQUAL(403, request("POST", p_sig, ok));
    TEST_ASSERT_EQUAL(404, request("POST", "/rec/AAAA", ok));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, "{"));
    TEST_ASSERT_EQUAL(400, request("POST", "/rec/AAAA", "{")); /* body checked before kid */
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, "{\"kty\":\"oct\",\"k\":\"AA\"}"));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, subst(ok, "ECMR", "ES512")));
    TEST_ASSERT_EQUAL(200, request("POST", p_exc, subst(ok, "\"alg\":\"ECMR\",", "")));
    TEST_ASSERT_EQUAL(
        403, request("POST", p_exc, subst(ok, "\"kty\"", "\"key_ops\":[\"sign\"],\"kty\"")));
    TEST_ASSERT_EQUAL(
        200, request("POST", p_exc, subst(ok, "\"kty\"", "\"key_ops\":[\"deriveKey\"],\"kty\"")));
    TEST_ASSERT_EQUAL(403, request("POST", p_exc, subst(ok, "\"kty\"", "\"use\":\"sig\",\"kty\"")));
    TEST_ASSERT_EQUAL(403, request("POST", p_exc, subst(ok, "\"kty\"", "\"use\":\"enc\",\"kty\"")));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, subst(ok, "P-521", "P-256")));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, subst(ok, "AYYVH4nRRw", "AYYVH4nRRx")));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, ""));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, "[]"));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, subst(ok, "\"kty\"", "\"d\":\"AA\",\"kty\"")));
    TEST_ASSERT_EQUAL(400, request("POST", p_exc, NULL));
    static char big[PT_TANG_MAX_BODY + 2];
    memset(big, 'a', sizeof(big) - 1);
    TEST_ASSERT_EQUAL(413, request("POST", p_exc, big));
    TEST_ASSERT_EQUAL(2, ev_ok);
    TEST_ASSERT_EQUAL(16, ev_denied);
}

static void test_lock_refuses_rec(void)
{
    char p[128];
    char body[512];
    snprintf(body, sizeof(body), "%s", rec_body());
    snprintf(p, sizeof(p), "/rec/%s", KID_EXC);
    pt_tang_set_locked(&tang, true);
    TEST_ASSERT_EQUAL(403, request("POST", p, body));
    TEST_ASSERT_EQUAL(0, resp.body_len);
    TEST_ASSERT_EQUAL(200, request("GET", "/adv", NULL)); /* advertisement unaffected */
    pt_tang_set_locked(&tang, false);
    TEST_ASSERT_EQUAL(200, request("POST", p, body));
}

static void test_no_keys_and_small_buffer(void)
{
    pt_tang_wipe(&tang);
    pt_tang_init(&tang);
    TEST_ASSERT_EQUAL(500, request("GET", "/adv", NULL));
    char p[128];
    char body[512];
    snprintf(body, sizeof(body), "%s", rec_body());
    snprintf(p, sizeof(p), "/rec/%s", KID_EXC);
    TEST_ASSERT_EQUAL(500, request("POST", p, body));
    TEST_ASSERT_EQUAL(PT_OK, pt_keystore_ensure(pt_tang_keystore(&tang)));
    TEST_ASSERT_EQUAL(200, request("GET", "/adv", NULL));
    pt_tang_req_t req;
    pt_tang_route("GET", "/adv", 4, &req);
    char tiny[64];
    pt_tang_handle(&tang, &req, NULL, 0, tiny, sizeof(tiny), &resp);
    TEST_ASSERT_EQUAL(500, resp.status);
    TEST_ASSERT_EQUAL(0, resp.body_len);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_routing_matches_upstream);
    RUN_TEST(test_adv_payload_equals_upstream);
    RUN_TEST(test_adv_kid_signed_twice_like_upstream);
    RUN_TEST(test_adv_after_rotation);
    RUN_TEST(test_rec_byte_exact_with_upstream);
    RUN_TEST(test_rec_with_tang_pub);
    RUN_TEST(test_rec_status_matrix_matches_upstream);
    RUN_TEST(test_lock_refuses_rec);
    RUN_TEST(test_no_keys_and_small_buffer);
    return UNITY_END();
}
