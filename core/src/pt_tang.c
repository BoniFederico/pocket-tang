#include "pt/pt_tang.h"
#include "pt/pt_b64url.h"
#include "pt/pt_json.h"
#include "pt/pt_jwk.h"
#include "pt/pt_version.h"

#include <string.h>

/* base64url('{"alg":"ES512","cty":"jwk-set+json"}'), identical to upstream tang. */
static const char PROTECTED_B64[] = "eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9";

static const char CT_JOSE[] = "application/jose+json";
static const char CT_JWK[] = "application/jwk+json";
static const char CT_JSON[] = "application/json";

#define OPS_VERIFY (1u << PT_OP_VERIFY)
#define OPS_DERIVE (1u << PT_OP_DERIVE_KEY)

void pt_tang_init(pt_tang_t *t)
{
    memset(t, 0, sizeof(*t));
    pt_keystore_init(&t->ks);
    t->include_tang_pub = true;
}

void pt_tang_wipe(pt_tang_t *t)
{
    pt_keystore_wipe(&t->ks);
    pt_zeroize(t, sizeof(*t));
}

pt_keystore_t *pt_tang_keystore(pt_tang_t *t)
{
    return &t->ks;
}

void pt_tang_set_event_cb(pt_tang_t *t, pt_tang_event_cb cb, void *ctx)
{
    t->cb = cb;
    t->cb_ctx = ctx;
}

void pt_tang_set_locked(pt_tang_t *t, bool locked)
{
    t->locked = locked;
}

static void emit(const pt_tang_t *t, pt_tang_event_t ev, int status, const char *kid)
{
    if (t->cb != NULL) {
        t->cb(t->cb_ctx, ev, status, kid != NULL ? kid : "");
    }
}

/* ----------------------------------------------------------------------------------------- */
/* Advertisement cache                                                                       */
/* ----------------------------------------------------------------------------------------- */

pt_err_t pt_tang_refresh(pt_tang_t *t)
{
    if (t->adv_valid && t->adv_generation == t->ks.generation) {
        return PT_OK;
    }
    t->adv_valid = false;
    const pt_key_t *sig = pt_keystore_active(&t->ks, PT_ALG_ES512);
    const pt_key_t *exc = pt_keystore_active(&t->ks, PT_ALG_ECMR);
    if (sig == NULL || exc == NULL) {
        return PT_ERR_STATE;
    }
    /* Payload: {"keys":[<active keys, oldest first>]}; signing keys advertise "verify". */
    char json[1200];
    pt_jw_t w;
    pt_jw_init(&w, json, sizeof(json));
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "keys");
    pt_jw_arr_begin(&w);
    for (unsigned i = 0; i < t->ks.count; i++) {
        const pt_key_t *k = &t->ks.keys[i];
        if (!k->rotated) {
            pt_jwk_write_public(&w, &k->pub, k->alg,
                                k->alg == PT_ALG_ES512 ? OPS_VERIFY : OPS_DERIVE);
        }
    }
    pt_jw_arr_end(&w);
    pt_jw_obj_end(&w);
    size_t json_len = 0;
    pt_err_t err = pt_jw_finish(&w, &json_len);
    if (err != PT_OK) {
        return err;
    }
    err = pt_b64url_encode((const uint8_t *)json, json_len, t->payload_b64, sizeof(t->payload_b64),
                           &t->payload_b64_len);
    if (err != PT_OK) {
        return err;
    }
    /* JWS signing input: ASCII(BASE64URL(protected) || '.' || BASE64URL(payload)) */
    const pt_iovec_t in[3] = {
        {PROTECTED_B64, sizeof(PROTECTED_B64) - 1},
        {".", 1},
        {t->payload_b64, t->payload_b64_len},
    };
    for (unsigned i = 0; i < t->ks.count; i++) {
        if (t->ks.keys[i].alg != PT_ALG_ES512) {
            continue;
        }
        err = pt_es512_sign(t->ks.keys[i].d, in, 3, t->sig[i]);
        if (err != PT_OK) {
            return err;
        }
    }
    t->adv_generation = t->ks.generation;
    t->adv_valid = true;
    return PT_OK;
}

/* Write one {"protected":..,"signature":..} pair members (no braces). */
static void write_sig_members(pt_jw_t *w, const uint8_t sig[PT_ES512_SIG_LEN])
{
    pt_jw_key(w, "protected");
    pt_jw_str(w, PROTECTED_B64);
    pt_jw_key(w, "signature");
    pt_jw_b64url(w, sig, PT_ES512_SIG_LEN);
}

/*
 * Serve /adv (extra == NULL) or /adv/{kid} (extra = the requested signing key). Like upstream,
 * the signers are all active ES512 keys plus the requested key (even if already present). A
 * single signer uses the flattened JWS JSON serialisation, several use the general one.
 */
static int serve_adv(const pt_tang_t *t, const pt_key_t *extra, char *out, size_t cap, size_t *len)
{
    const uint8_t *signers[PT_KEYS_MAX + 1];
    unsigned n = 0;
    for (unsigned i = 0; i < t->ks.count; i++) {
        if (t->ks.keys[i].alg == PT_ALG_ES512 && !t->ks.keys[i].rotated) {
            signers[n++] = t->sig[i];
        }
    }
    if (extra != NULL) {
        signers[n++] = t->sig[extra - t->ks.keys];
    }
    pt_jw_t w;
    pt_jw_init(&w, out, cap);
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "payload");
    pt_jw_strn(&w, t->payload_b64, t->payload_b64_len);
    if (n == 1) {
        write_sig_members(&w, signers[0]);
    } else {
        pt_jw_key(&w, "signatures");
        pt_jw_arr_begin(&w);
        for (unsigned i = 0; i < n; i++) {
            pt_jw_obj_begin(&w);
            write_sig_members(&w, signers[i]);
            pt_jw_obj_end(&w);
        }
        pt_jw_arr_end(&w);
    }
    pt_jw_obj_end(&w);
    return pt_jw_finish(&w, len) == PT_OK ? 200 : 500;
}

/* ----------------------------------------------------------------------------------------- */
/* Routing                                                                                   */
/* ----------------------------------------------------------------------------------------- */

static bool is_kid_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
           c == '-';
}

/*
 * Match the upstream route regexes: one or more slashes, <name>, then either optional trailing
 * slashes only (want_kid false) or one or more slashes and a kid of [0-9A-Za-z_-]+ (want_kid true).
 * Returns true on match and copies the kid. Kids longer than PT_KID_MAX never match a key and
 * are treated as not found.
 */
static bool match_path(const char *p, size_t len, const char *name, bool want_kid, char *kid,
                       size_t *kid_len)
{
    size_t i = 0;
    size_t nl = strlen(name);
    if (len == 0 || p[0] != '/') {
        return false;
    }
    while (i < len && p[i] == '/') {
        i++;
    }
    if (len - i < nl || memcmp(p + i, name, nl) != 0) {
        return false;
    }
    i += nl;
    if (!want_kid) {
        while (i < len && p[i] == '/') {
            i++;
        }
        return i == len;
    }
    if (i >= len || p[i] != '/') {
        return false;
    }
    while (i < len && p[i] == '/') {
        i++;
    }
    size_t start = i;
    while (i < len && is_kid_char(p[i])) {
        i++;
    }
    if (i != len || i == start) {
        return false;
    }
    size_t n = i - start;
    if (n > PT_KID_MAX) {
        n = PT_KID_MAX + 1; /* marker: too long, cannot match */
        *kid_len = n;
        kid[0] = '\0';
        return true;
    }
    memcpy(kid, p + start, n);
    kid[n] = '\0';
    *kid_len = n;
    return true;
}

void pt_tang_route(const char *method, const char *target, size_t len, pt_tang_req_t *req)
{
    memset(req, 0, sizeof(*req));
    req->status = 404;
    if (method == NULL || target == NULL) {
        return;
    }
    bool get = strcmp(method, "GET") == 0;
    bool post = strcmp(method, "POST") == 0;
    if (match_path(target, len, "adv", false, req->kid, &req->kid_len)) {
        req->route = PT_ROUTE_ADV;
        req->status = get ? 0 : 405;
    } else if (match_path(target, len, "adv", true, req->kid, &req->kid_len)) {
        req->route = PT_ROUTE_ADV_KID;
        req->status = get ? 0 : 405;
    } else if (match_path(target, len, "rec", true, req->kid, &req->kid_len)) {
        req->route = PT_ROUTE_REC;
        req->status = post ? 0 : 405;
    } else if (match_path(target, len, "version", false, req->kid, &req->kid_len)) {
        req->route = PT_ROUTE_VERSION;
        req->status = get ? 0 : 405;
    } else {
        req->route = PT_ROUTE_NONE;
        req->kid_len = 0;
        req->kid[0] = '\0';
    }
}

/* ----------------------------------------------------------------------------------------- */
/* Recovery                                                                                  */
/* ----------------------------------------------------------------------------------------- */

#define REC_TOKENS 48

/* Validation order mirrors tangd rec(): parse 400, permission 403, kty/alg 400, keys 500,
 * kid 404, server key 403, exchange 400. */
static int serve_rec(pt_tang_t *t, const pt_tang_req_t *req, const uint8_t *body, size_t body_len,
                     char *out, size_t cap, size_t *len)
{
    pt_json_tok_t toks[REC_TOKENS];
    pt_json_doc_t doc;
    if (pt_json_parse((const char *)body, body_len, toks, REC_TOKENS, &doc) != PT_OK ||
        pt_json_type(&doc, 0) != PT_JSON_OBJECT) {
        return 400;
    }
    if (!pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY)) {
        return 403;
    }
    int kty = pt_json_obj_get(&doc, 0, "kty");
    if (kty < 0 || !pt_json_str_eq(&doc, kty, "EC")) {
        return 400;
    }
    pt_alg_t alg = PT_ALG_NONE;
    if (pt_jwk_get_alg(&doc, 0, &alg) != PT_OK || (alg != PT_ALG_NONE && alg != PT_ALG_ECMR)) {
        return 400;
    }
    if (pt_keystore_active(&t->ks, PT_ALG_ECMR) == NULL) {
        return 500;
    }
    const pt_key_t *key = pt_keystore_find(&t->ks, req->kid, req->kid_len);
    if (key == NULL) {
        return 404;
    }
    if (key->alg != PT_ALG_ECMR) {
        return 403;
    }
    pt_jwk_t cli;
    if (pt_jwk_parse(&doc, 0, false, &cli) != PT_OK) {
        return 400; /* wrong curve, bad point, private key material... */
    }
    pt_p521_point_t res;
    if (pt_p521_ecmr(key->d, &cli.pub, &res) != PT_OK) {
        return 400;
    }
    pt_jw_t w;
    pt_jw_init(&w, out, cap);
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "alg");
    pt_jw_str(&w, "ECMR");
    pt_jw_key(&w, "crv");
    pt_jw_str(&w, "P-521");
    pt_jw_key(&w, "key_ops");
    pt_jw_arr_begin(&w);
    pt_jw_str(&w, "deriveKey");
    pt_jw_arr_end(&w);
    pt_jw_key(&w, "kty");
    pt_jw_str(&w, "EC");
    if (t->include_tang_pub) {
        pt_jw_key(&w, "tang_pub");
        pt_jwk_write_public(&w, &key->pub, PT_ALG_ECMR, OPS_DERIVE);
    }
    pt_jw_key(&w, "x");
    pt_jw_b64url(&w, res.x, PT_P521_LEN);
    pt_jw_key(&w, "y");
    pt_jw_b64url(&w, res.y, PT_P521_LEN);
    pt_jw_obj_end(&w);
    pt_zeroize(&res, sizeof(res));
    return pt_jw_finish(&w, len) == PT_OK ? 200 : 500;
}

static int serve_version(char *out, size_t cap, size_t *len)
{
    pt_jw_t w;
    pt_jw_init(&w, out, cap);
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "name");
    pt_jw_str(&w, "pocket-tang");
    pt_jw_key(&w, "version");
    pt_jw_str(&w, pt_version());
    pt_jw_obj_end(&w);
    return pt_jw_finish(&w, len) == PT_OK ? 200 : 500;
}

void pt_tang_handle(pt_tang_t *t, const pt_tang_req_t *req, const uint8_t *body, size_t body_len,
                    char *out, size_t cap, pt_tang_resp_t *resp)
{
    size_t len = 0;
    int status = 500;
    const char *ct = NULL;
    resp->status = 500;
    resp->content_type = NULL;
    resp->body_len = 0;
    if (req == NULL || out == NULL || cap == 0) {
        return;
    }
    if (req->status != 0) {
        resp->status = req->status;
        return;
    }
    switch (req->route) {
    case PT_ROUTE_ADV:
    case PT_ROUTE_ADV_KID: {
        if (pt_tang_refresh(t) != PT_OK) {
            status = 500;
            break;
        }
        const pt_key_t *extra = NULL;
        if (req->route == PT_ROUTE_ADV_KID) {
            extra = pt_keystore_find(&t->ks, req->kid, req->kid_len);
            if (extra == NULL || extra->alg != PT_ALG_ES512) {
                status = 404;
                break;
            }
        }
        status = serve_adv(t, extra, out, cap, &len);
        ct = CT_JOSE;
        emit(t, PT_EV_ADV, status, req->kid);
        break;
    }
    case PT_ROUTE_REC:
        if (body_len > PT_TANG_MAX_BODY) {
            status = 413;
        } else if (t->locked) {
            status = 403;
        } else if (body == NULL) {
            status = 400;
        } else {
            status = serve_rec(t, req, body, body_len, out, cap, &len);
        }
        ct = CT_JWK;
        emit(t, status == 200 ? PT_EV_REC_OK : PT_EV_REC_DENIED, status, req->kid);
        break;
    case PT_ROUTE_VERSION:
        status = serve_version(out, cap, &len);
        ct = CT_JSON;
        break;
    default:
        status = 404;
        break;
    }
    resp->status = status;
    if (status == 200) {
        resp->content_type = ct;
        resp->body_len = len;
    } else {
        out[0] = '\0';
    }
}
