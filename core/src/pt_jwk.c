#include "pt/pt_jwk.h"
#include "pt/pt_b64url.h"

#include <string.h>

static const char *const OP_NAMES[] = {"sign", "verify", "deriveKey"};

bool pt_jwk_permits(const pt_json_doc_t *doc, int obj, bool required, pt_keyop_t op)
{
    if (pt_json_type(doc, obj) != PT_JSON_OBJECT || (unsigned)op > PT_OP_DERIVE_KEY) {
        return false;
    }
    int ko = pt_json_obj_get(doc, obj, "key_ops");
    int use = pt_json_obj_get(doc, obj, "use");
    if (ko == -(int)PT_ERR_DUPLICATE || use == -(int)PT_ERR_DUPLICATE) {
        return false;
    }
    if (use >= 0 && pt_json_type(doc, use) != PT_JSON_STRING) {
        return false; /* libjose: json_unpack "s?s" fails */
    }
    if (ko < 0 && use < 0) {
        return !required;
    }
    if (ko >= 0 && pt_json_arr_has_str(doc, ko, OP_NAMES[op])) {
        return true;
    }
    if (use >= 0) {
        if (pt_json_str_eq(doc, use, "sig")) {
            return op == PT_OP_SIGN || op == PT_OP_VERIFY;
        }
        /* "enc" maps to encrypt/decrypt/wrapKey/unwrapKey only: never sign/verify/deriveKey. */
    }
    return false;
}

pt_err_t pt_jwk_get_alg(const pt_json_doc_t *doc, int obj, pt_alg_t *alg)
{
    int a = pt_json_obj_get(doc, obj, "alg");
    if (a == -(int)PT_ERR_NOTFOUND) {
        *alg = PT_ALG_NONE;
        return PT_OK;
    }
    if (a < 0 || pt_json_type(doc, a) != PT_JSON_STRING) {
        return PT_ERR_INVALID;
    }
    if (pt_json_str_eq(doc, a, "ES512")) {
        *alg = PT_ALG_ES512;
    } else if (pt_json_str_eq(doc, a, "ECMR")) {
        *alg = PT_ALG_ECMR;
    } else {
        *alg = PT_ALG_OTHER;
    }
    return PT_OK;
}

/* Fetch a string member that must be present exactly once. */
static int get_str(const pt_json_doc_t *doc, int obj, const char *name)
{
    int t = pt_json_obj_get(doc, obj, name);
    if (t < 0) {
        return t;
    }
    return pt_json_type(doc, t) == PT_JSON_STRING ? t : -(int)PT_ERR_INVALID;
}

static pt_err_t get_coord(const pt_json_doc_t *doc, int obj, const char *name,
                          uint8_t out[PT_P521_LEN])
{
    int t = get_str(doc, obj, name);
    if (t < 0) {
        return PT_ERR_INVALID;
    }
    const pt_json_tok_t *tk = &doc->toks[t];
    if (tk->flags & PT_JSON_F_ESCAPED) {
        return PT_ERR_INVALID; /* base64url never needs escapes */
    }
    return pt_b64url_decode_exact(doc->buf + tk->start, tk->end - tk->start, out, PT_P521_LEN);
}

pt_err_t pt_jwk_parse(const pt_json_doc_t *doc, int obj, bool allow_private, pt_jwk_t *out)
{
    if (out == NULL) {
        return PT_ERR_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (pt_json_type(doc, obj) != PT_JSON_OBJECT) {
        return PT_ERR_INVALID;
    }
    int kty = get_str(doc, obj, "kty");
    if (kty < 0 || !pt_json_str_eq(doc, kty, "EC")) {
        return PT_ERR_INVALID;
    }
    int crv = get_str(doc, obj, "crv");
    if (crv < 0) {
        return PT_ERR_INVALID;
    }
    if (!pt_json_str_eq(doc, crv, "P-521")) {
        return PT_ERR_UNSUPPORTED;
    }
    pt_err_t err = pt_jwk_get_alg(doc, obj, &out->alg);
    if (err != PT_OK) {
        return err;
    }
    if (get_coord(doc, obj, "x", out->pub.x) != PT_OK ||
        get_coord(doc, obj, "y", out->pub.y) != PT_OK) {
        return PT_ERR_INVALID;
    }
    if (pt_p521_point_check(&out->pub) != PT_OK) {
        return PT_ERR_INVALID;
    }
    int d = pt_json_obj_get(doc, obj, "d");
    if (d == -(int)PT_ERR_NOTFOUND) {
        return PT_OK;
    }
    if (!allow_private) {
        return PT_ERR_FORBIDDEN;
    }
    if (get_coord(doc, obj, "d", out->d) != PT_OK || pt_p521_scalar_check(out->d) != PT_OK) {
        pt_jwk_wipe(out);
        return PT_ERR_INVALID;
    }
    /* The private scalar must match the advertised public point. */
    pt_p521_point_t chk;
    if (pt_p521_public(out->d, &chk) != PT_OK || !pt_ct_memeq(&chk, &out->pub, sizeof(chk))) {
        pt_jwk_wipe(out);
        return PT_ERR_INVALID;
    }
    out->has_d = true;
    return PT_OK;
}

void pt_jwk_write_public(pt_jw_t *w, const pt_p521_point_t *pub, pt_alg_t alg, unsigned ops_mask)
{
    pt_jw_obj_begin(w);
    if (alg == PT_ALG_ES512) {
        pt_jw_key(w, "alg");
        pt_jw_str(w, "ES512");
    } else if (alg == PT_ALG_ECMR) {
        pt_jw_key(w, "alg");
        pt_jw_str(w, "ECMR");
    }
    pt_jw_key(w, "crv");
    pt_jw_str(w, "P-521");
    if (ops_mask != 0) {
        pt_jw_key(w, "key_ops");
        pt_jw_arr_begin(w);
        for (unsigned i = 0; i < sizeof(OP_NAMES) / sizeof(OP_NAMES[0]); i++) {
            if (ops_mask & (1u << i)) {
                pt_jw_str(w, OP_NAMES[i]);
            }
        }
        pt_jw_arr_end(w);
    }
    pt_jw_key(w, "kty");
    pt_jw_str(w, "EC");
    pt_jw_key(w, "x");
    pt_jw_b64url(w, pub->x, PT_P521_LEN);
    pt_jw_key(w, "y");
    pt_jw_b64url(w, pub->y, PT_P521_LEN);
    pt_jw_obj_end(w);
}

pt_err_t pt_jwk_thumbprint(const pt_p521_point_t *pub, pt_hash_alg_t alg, uint8_t *out)
{
    char buf[256];
    pt_jw_t w;
    pt_jw_init(&w, buf, sizeof(buf));
    pt_jwk_write_public(&w, pub, PT_ALG_NONE, 0);
    size_t len = 0;
    pt_err_t err = pt_jw_finish(&w, &len);
    if (err != PT_OK) {
        return err;
    }
    pt_iovec_t iov = {buf, len};
    return pt_hash(alg, &iov, 1, out);
}

pt_err_t pt_jwk_thumbprint_b64(const pt_p521_point_t *pub, pt_hash_alg_t alg, char *out, size_t cap)
{
    uint8_t h[PT_HASH_MAX_LEN];
    pt_err_t err = pt_jwk_thumbprint(pub, alg, h);
    if (err != PT_OK) {
        return err;
    }
    return pt_b64url_encode(h, pt_hash_len(alg), out, cap, NULL);
}

void pt_jwk_wipe(pt_jwk_t *jwk)
{
    if (jwk != NULL) {
        pt_zeroize(jwk, sizeof(*jwk));
    }
}
