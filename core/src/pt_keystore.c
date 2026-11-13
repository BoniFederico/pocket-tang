#include "pt/pt_keystore.h"
#include "pt/pt_b64url.h"

#include <string.h>

#define BLOB_MAGIC   "PTKS"
#define BLOB_VERSION 1
#define BLOB_HDR     8u
#define BLOB_KEY     (2u + 3u * PT_P521_LEN)
#define FLAG_ROTATED 0x01u
#define OFF_D        ((size_t)2)
#define OFF_X        (OFF_D + (size_t)PT_P521_LEN)
#define OFF_Y        (OFF_X + (size_t)PT_P521_LEN)

void pt_keystore_init(pt_keystore_t *ks)
{
    memset(ks, 0, sizeof(*ks));
}

void pt_keystore_wipe(pt_keystore_t *ks)
{
    pt_zeroize(ks, sizeof(*ks));
}

static pt_err_t compute_thumbprints(pt_key_t *k)
{
    for (int h = 0; h < PT_HASH_COUNT; h++) {
        pt_err_t err = pt_jwk_thumbprint(&k->pub, (pt_hash_alg_t)h, k->thp[h]);
        if (err == PT_ERR_UNSUPPORTED) {
            memset(k->thp[h], 0, sizeof(k->thp[h]));
            continue; /* backend lacks this hash: such kids will simply not match */
        }
        if (err != PT_OK) {
            return err;
        }
    }
    return PT_OK;
}

static pt_err_t gen_key(pt_key_t *k, pt_alg_t alg)
{
    memset(k, 0, sizeof(*k));
    k->alg = alg;
    pt_err_t err = pt_p521_keygen(k->d, &k->pub);
    if (err == PT_OK) {
        err = compute_thumbprints(k);
    }
    if (err != PT_OK) {
        pt_zeroize(k, sizeof(*k));
    }
    return err;
}

const pt_key_t *pt_keystore_active(const pt_keystore_t *ks, pt_alg_t alg)
{
    for (unsigned i = ks->count; i-- > 0;) {
        if (!ks->keys[i].rotated && ks->keys[i].alg == alg) {
            return &ks->keys[i];
        }
    }
    return NULL;
}

/* Generate a new pair into the two slots after the current keys (not yet committed). */
static pt_err_t gen_pair(pt_keystore_t *ks)
{
    if (ks->count + 2 > PT_KEYS_MAX) {
        return PT_ERR_LIMIT;
    }
    pt_err_t err = gen_key(&ks->keys[ks->count], PT_ALG_ES512);
    if (err != PT_OK) {
        return err;
    }
    err = gen_key(&ks->keys[ks->count + 1], PT_ALG_ECMR);
    if (err != PT_OK) {
        pt_zeroize(&ks->keys[ks->count], sizeof(pt_key_t));
        return err;
    }
    return PT_OK;
}

pt_err_t pt_keystore_ensure(pt_keystore_t *ks)
{
    if (pt_keystore_active(ks, PT_ALG_ES512) != NULL &&
        pt_keystore_active(ks, PT_ALG_ECMR) != NULL) {
        return PT_OK;
    }
    return pt_keystore_rotate(ks);
}

pt_err_t pt_keystore_rotate(pt_keystore_t *ks)
{
    pt_err_t err = gen_pair(ks);
    if (err != PT_OK) {
        return err;
    }
    for (unsigned i = 0; i < ks->count; i++) {
        ks->keys[i].rotated = true;
    }
    ks->count += 2;
    ks->generation++;
    return PT_OK;
}

pt_err_t pt_keystore_import(pt_keystore_t *ks, const pt_jwk_t *jwk, bool rotated)
{
    if (jwk == NULL || !jwk->has_d || (jwk->alg != PT_ALG_ES512 && jwk->alg != PT_ALG_ECMR)) {
        return PT_ERR_INVALID;
    }
    if (ks->count >= PT_KEYS_MAX) {
        return PT_ERR_LIMIT;
    }
    for (unsigned i = 0; i < ks->count; i++) {
        if (pt_ct_memeq(&ks->keys[i].pub, &jwk->pub, sizeof(jwk->pub))) {
            return PT_ERR_DUPLICATE;
        }
    }
    pt_key_t *k = &ks->keys[ks->count];
    memset(k, 0, sizeof(*k));
    memcpy(k->d, jwk->d, PT_P521_LEN);
    k->pub = jwk->pub;
    k->alg = jwk->alg;
    k->rotated = rotated;
    pt_err_t err = compute_thumbprints(k);
    if (err != PT_OK) {
        pt_zeroize(k, sizeof(*k));
        return err;
    }
    if (!rotated) {
        for (unsigned i = 0; i < ks->count; i++) {
            if (ks->keys[i].alg == jwk->alg) {
                ks->keys[i].rotated = true;
            }
        }
    }
    ks->count++;
    ks->generation++;
    return PT_OK;
}

unsigned pt_keystore_count(const pt_keystore_t *ks)
{
    return ks->count;
}

const pt_key_t *pt_keystore_at(const pt_keystore_t *ks, unsigned i)
{
    return i < ks->count ? &ks->keys[i] : NULL;
}

/* Index of the key matching @p kid or -1. Thumbprints are public: no constant time needed. */
static int find_idx(const pt_keystore_t *ks, const char *kid, size_t kid_len)
{
    uint8_t raw[PT_HASH_MAX_LEN];
    size_t raw_len = 0;
    if (kid == NULL || kid_len == 0 || kid_len > PT_KID_MAX ||
        pt_b64url_decode(kid, kid_len, raw, sizeof(raw), &raw_len) != PT_OK) {
        return -1;
    }
    for (int h = 0; h < PT_HASH_COUNT; h++) {
        if (pt_hash_len((pt_hash_alg_t)h) != raw_len) {
            continue;
        }
        for (unsigned i = 0; i < ks->count; i++) {
            if (memcmp(ks->keys[i].thp[h], raw, raw_len) == 0) {
                return (int)i;
            }
        }
    }
    return -1;
}

const pt_key_t *pt_keystore_find(const pt_keystore_t *ks, const char *kid, size_t kid_len)
{
    int i = find_idx(ks, kid, kid_len);
    return i >= 0 ? &ks->keys[i] : NULL;
}

static void remove_at(pt_keystore_t *ks, unsigned i)
{
    memmove(&ks->keys[i], &ks->keys[i + 1], (ks->count - i - 1) * sizeof(pt_key_t));
    ks->count--;
    pt_zeroize(&ks->keys[ks->count], sizeof(pt_key_t));
    ks->generation++;
}

pt_err_t pt_keystore_purge(pt_keystore_t *ks, const char *kid, size_t kid_len)
{
    int i = find_idx(ks, kid, kid_len);
    if (i < 0) {
        return PT_ERR_NOTFOUND;
    }
    if (!ks->keys[i].rotated) {
        return PT_ERR_FORBIDDEN;
    }
    remove_at(ks, (unsigned)i);
    return PT_OK;
}

unsigned pt_keystore_purge_rotated(pt_keystore_t *ks)
{
    unsigned removed = 0;
    for (unsigned i = ks->count; i-- > 0;) {
        if (ks->keys[i].rotated) {
            remove_at(ks, i);
            removed++;
        }
    }
    return removed;
}

pt_err_t pt_keystore_save(const pt_keystore_t *ks, uint8_t *out, size_t cap, size_t *len)
{
    size_t need = PT_KEYSTORE_BLOB_LEN(ks->count);
    if (out == NULL || cap < need) {
        return PT_ERR_NOSPACE;
    }
    memcpy(out, BLOB_MAGIC, 4);
    out[4] = BLOB_VERSION;
    out[5] = (uint8_t)ks->count;
    out[6] = 0;
    out[7] = 0;
    uint8_t *p = out + BLOB_HDR;
    for (unsigned i = 0; i < ks->count; i++) {
        const pt_key_t *k = &ks->keys[i];
        p[0] = (uint8_t)k->alg;
        p[1] = k->rotated ? FLAG_ROTATED : 0u;
        memcpy(p + OFF_D, k->d, PT_P521_LEN);
        memcpy(p + OFF_X, k->pub.x, PT_P521_LEN);
        memcpy(p + OFF_Y, k->pub.y, PT_P521_LEN);
        p += BLOB_KEY;
    }
    pt_iovec_t iov = {out, (size_t)(p - out)};
    pt_err_t err = pt_hash(PT_HASH_SHA256, &iov, 1, p);
    if (err != PT_OK) {
        pt_zeroize(out, need);
        return err;
    }
    *len = need;
    return PT_OK;
}

pt_err_t pt_keystore_load(pt_keystore_t *ks, const uint8_t *in, size_t len)
{
    pt_keystore_init(ks);
    if (in == NULL || len < BLOB_HDR + 32u || memcmp(in, BLOB_MAGIC, 4) != 0 ||
        in[4] != BLOB_VERSION || in[5] > PT_KEYS_MAX || in[6] != 0 || in[7] != 0 ||
        len != PT_KEYSTORE_BLOB_LEN(in[5])) {
        return PT_ERR_INVALID;
    }
    unsigned n = in[5];
    uint8_t sum[32];
    pt_iovec_t iov = {in, len - 32u};
    if (pt_hash(PT_HASH_SHA256, &iov, 1, sum) != PT_OK || !pt_ct_memeq(sum, in + len - 32u, 32)) {
        return PT_ERR_INVALID;
    }
    const uint8_t *p = in + BLOB_HDR;
    pt_err_t err = PT_OK;
    for (unsigned i = 0; i < n && err == PT_OK; i++, p += BLOB_KEY) {
        pt_key_t *k = &ks->keys[i];
        if ((p[0] != PT_ALG_ES512 && p[0] != PT_ALG_ECMR) || (p[1] & ~FLAG_ROTATED) != 0) {
            err = PT_ERR_INVALID;
            break;
        }
        k->alg = (pt_alg_t)p[0];
        k->rotated = (p[1] & FLAG_ROTATED) != 0;
        memcpy(k->d, p + OFF_D, PT_P521_LEN);
        memcpy(k->pub.x, p + OFF_X, PT_P521_LEN);
        memcpy(k->pub.y, p + OFF_Y, PT_P521_LEN);
        pt_p521_point_t chk;
        if (pt_p521_public(k->d, &chk) != PT_OK || !pt_ct_memeq(&chk, &k->pub, sizeof(chk))) {
            err = PT_ERR_INVALID;
            break;
        }
        err = compute_thumbprints(k);
        ks->count = i + 1;
    }
    if (err == PT_OK) {
        /* At most one active key per algorithm. */
        unsigned act_sig = 0;
        unsigned act_exc = 0;
        for (unsigned i = 0; i < ks->count; i++) {
            if (!ks->keys[i].rotated) {
                act_sig += ks->keys[i].alg == PT_ALG_ES512;
                act_exc += ks->keys[i].alg == PT_ALG_ECMR;
            }
        }
        if (act_sig > 1 || act_exc > 1) {
            err = PT_ERR_INVALID;
        }
    }
    if (err != PT_OK) {
        pt_keystore_wipe(ks);
        return err;
    }
    ks->generation = 1;
    return PT_OK;
}
