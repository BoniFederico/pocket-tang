/*
 * Mbed TLS 3.6 backend for pt_crypto.h.
 *
 * Only public Mbed TLS APIs are used (no MBEDTLS_PRIVATE field access), so the same file builds
 * against upstream Mbed TLS on the host and against the ESP-IDF fork (with hardware MPI) on
 * the target.
 */
#include "pt/pt_crypto.h"

#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#if !defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#error "Pocket Tang requires MBEDTLS_ECP_DP_SECP521R1_ENABLED"
#endif
#if !defined(MBEDTLS_SHA512_C) || !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_SHA1_C)
#error "Pocket Tang requires SHA-1, SHA-256 and SHA-512 in Mbed TLS"
#endif

/* Uncompressed SEC1 encoding: 0x04 || X || Y */
#define SEC1_LEN ((size_t)1 + (size_t)2 * PT_P521_LEN)

static pt_rng_fn g_rng;
static void *g_rng_ctx;

void pt_crypto_set_rng(pt_rng_fn fn, void *ctx)
{
    g_rng = fn;
    g_rng_ctx = ctx;
}

pt_err_t pt_crypto_random(uint8_t *buf, size_t len)
{
    if (g_rng == NULL) {
        return PT_ERR_STATE;
    }
    return g_rng(g_rng_ctx, buf, len) == 0 ? PT_OK : PT_ERR_CRYPTO;
}

/* Adapter with the Mbed TLS f_rng signature. */
static int mbed_rng(void *unused, unsigned char *buf, size_t len)
{
    (void)unused;
    return pt_crypto_random(buf, len) == PT_OK ? 0 : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}

/* ----------------------------------------------------------------------------------------- */
/* Hashes                                                                                    */
/* ----------------------------------------------------------------------------------------- */

size_t pt_hash_len(pt_hash_alg_t alg)
{
    switch (alg) {
    case PT_HASH_SHA1:
        return 20;
    case PT_HASH_SHA224:
        return 28;
    case PT_HASH_SHA256:
        return 32;
    case PT_HASH_SHA384:
        return 48;
    case PT_HASH_SHA512:
        return 64;
    default:
        return 0;
    }
}

pt_err_t pt_hash(pt_hash_alg_t alg, const pt_iovec_t *iov, size_t n, uint8_t *out)
{
    int rc = 0;
    if (out == NULL || (n > 0 && iov == NULL)) {
        return PT_ERR_INVALID;
    }
    switch (alg) {
    case PT_HASH_SHA1: {
        mbedtls_sha1_context c;
        mbedtls_sha1_init(&c);
        rc = mbedtls_sha1_starts(&c);
        for (size_t i = 0; rc == 0 && i < n; i++) {
            rc = mbedtls_sha1_update(&c, iov[i].ptr, iov[i].len);
        }
        if (rc == 0) {
            rc = mbedtls_sha1_finish(&c, out);
        }
        mbedtls_sha1_free(&c);
        break;
    }
    case PT_HASH_SHA224:
#if !defined(MBEDTLS_SHA224_C)
        return PT_ERR_UNSUPPORTED;
#endif
        /* fall through */
    case PT_HASH_SHA256: {
        mbedtls_sha256_context c;
        mbedtls_sha256_init(&c);
        rc = mbedtls_sha256_starts(&c, alg == PT_HASH_SHA224);
        for (size_t i = 0; rc == 0 && i < n; i++) {
            rc = mbedtls_sha256_update(&c, iov[i].ptr, iov[i].len);
        }
        if (rc == 0) {
            rc = mbedtls_sha256_finish(&c, out);
        }
        mbedtls_sha256_free(&c);
        break;
    }
    case PT_HASH_SHA384:
#if !defined(MBEDTLS_SHA384_C)
        return PT_ERR_UNSUPPORTED;
#endif
        /* fall through */
    case PT_HASH_SHA512: {
        mbedtls_sha512_context c;
        mbedtls_sha512_init(&c);
        rc = mbedtls_sha512_starts(&c, alg == PT_HASH_SHA384);
        for (size_t i = 0; rc == 0 && i < n; i++) {
            rc = mbedtls_sha512_update(&c, iov[i].ptr, iov[i].len);
        }
        if (rc == 0) {
            rc = mbedtls_sha512_finish(&c, out);
        }
        mbedtls_sha512_free(&c);
        break;
    }
    default:
        return PT_ERR_INVALID;
    }
    return rc == 0 ? PT_OK : PT_ERR_CRYPTO;
}

/* ----------------------------------------------------------------------------------------- */
/* P-521 helpers                                                                              */
/* ----------------------------------------------------------------------------------------- */

static int load_group(mbedtls_ecp_group *grp)
{
    mbedtls_ecp_group_init(grp);
    return mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP521R1);
}

static int point_read(const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt,
                      const pt_p521_point_t *in)
{
    uint8_t buf[SEC1_LEN];
    buf[0] = 0x04;
    memcpy(buf + 1, in->x, PT_P521_LEN);
    memcpy(buf + 1 + (size_t)PT_P521_LEN, in->y, PT_P521_LEN);
    int rc = mbedtls_ecp_point_read_binary(grp, pt, buf, sizeof(buf));
    if (rc == 0) {
        rc = mbedtls_ecp_check_pubkey(grp, pt);
    }
    return rc;
}

static int point_write(const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt, pt_p521_point_t *out)
{
    uint8_t buf[SEC1_LEN];
    size_t olen = 0;
    if (mbedtls_ecp_is_zero(pt)) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    int rc = mbedtls_ecp_point_write_binary(grp, pt, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf,
                                            sizeof(buf));
    if (rc != 0) {
        return rc;
    }
    if (olen != SEC1_LEN || buf[0] != 0x04) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    memcpy(out->x, buf + 1, PT_P521_LEN);
    memcpy(out->y, buf + 1 + (size_t)PT_P521_LEN, PT_P521_LEN);
    return 0;
}

static int scalar_read(const mbedtls_ecp_group *grp, mbedtls_mpi *d, const uint8_t in[PT_P521_LEN])
{
    int rc = mbedtls_mpi_read_binary(d, in, PT_P521_LEN);
    if (rc == 0) {
        rc = mbedtls_ecp_check_privkey(grp, d);
    }
    return rc;
}

pt_err_t pt_p521_point_check(const pt_p521_point_t *p)
{
    if (p == NULL) {
        return PT_ERR_INVALID;
    }
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt;
    mbedtls_ecp_point_init(&pt);
    int rc = load_group(&grp);
    if (rc == 0) {
        rc = point_read(&grp, &pt, p);
    }
    mbedtls_ecp_point_free(&pt);
    mbedtls_ecp_group_free(&grp);
    return rc == 0 ? PT_OK : PT_ERR_INVALID;
}

pt_err_t pt_p521_scalar_check(const uint8_t d[PT_P521_LEN])
{
    if (d == NULL) {
        return PT_ERR_INVALID;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi m;
    mbedtls_mpi_init(&m);
    int rc = load_group(&grp);
    if (rc == 0) {
        rc = scalar_read(&grp, &m, d);
    }
    mbedtls_mpi_free(&m); /* mbedtls_mpi_free zeroizes the limbs */
    mbedtls_ecp_group_free(&grp);
    return rc == 0 ? PT_OK : PT_ERR_INVALID;
}

pt_err_t pt_p521_public(const uint8_t d[PT_P521_LEN], pt_p521_point_t *pub)
{
    if (d == NULL || pub == NULL) {
        return PT_ERR_INVALID;
    }
    if (g_rng == NULL) {
        return PT_ERR_STATE; /* Mbed TLS 3.x requires an RNG for (blinded) scalar multiplication */
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi m;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&m);
    mbedtls_ecp_point_init(&q);
    pt_err_t err = PT_ERR_CRYPTO;
    if (load_group(&grp) == 0) {
        if (scalar_read(&grp, &m, d) != 0) {
            err = PT_ERR_INVALID;
        } else if (mbedtls_ecp_mul(&grp, &q, &m, &grp.G, mbed_rng, NULL) == 0 &&
                   point_write(&grp, &q, pub) == 0) {
            err = PT_OK;
        }
    }
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&m);
    mbedtls_ecp_group_free(&grp);
    return err;
}

pt_err_t pt_p521_keygen(uint8_t d[PT_P521_LEN], pt_p521_point_t *pub)
{
    if (d == NULL || pub == NULL) {
        return PT_ERR_INVALID;
    }
    if (g_rng == NULL) {
        return PT_ERR_STATE;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi m;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&m);
    mbedtls_ecp_point_init(&q);
    pt_err_t err = PT_ERR_CRYPTO;
    if (load_group(&grp) == 0 && mbedtls_ecp_gen_keypair(&grp, &m, &q, mbed_rng, NULL) == 0 &&
        mbedtls_mpi_write_binary(&m, d, PT_P521_LEN) == 0 && point_write(&grp, &q, pub) == 0) {
        err = PT_OK;
    }
    if (err != PT_OK) {
        pt_zeroize(d, PT_P521_LEN);
    }
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&m);
    mbedtls_ecp_group_free(&grp);
    return err;
}

pt_err_t pt_p521_ecmr(const uint8_t d[PT_P521_LEN], const pt_p521_point_t *in, pt_p521_point_t *out)
{
    if (d == NULL || in == NULL || out == NULL) {
        return PT_ERR_INVALID;
    }
    if (g_rng == NULL) {
        return PT_ERR_STATE;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi m;
    mbedtls_ecp_point p;
    mbedtls_ecp_point r;
    mbedtls_mpi_init(&m);
    mbedtls_ecp_point_init(&p);
    mbedtls_ecp_point_init(&r);
    pt_err_t err = PT_ERR_CRYPTO;
    if (load_group(&grp) != 0) {
        goto done;
    }
    if (point_read(&grp, &p, in) != 0 || scalar_read(&grp, &m, d) != 0) {
        err = PT_ERR_INVALID;
        goto done;
    }
    /* Mbed TLS randomises the projective coordinates of the input point (side channels). */
    if (mbedtls_ecp_mul(&grp, &r, &m, &p, mbed_rng, NULL) != 0) {
        goto done;
    }
    if (point_write(&grp, &r, out) != 0) {
        goto done;
    }
    err = PT_OK;
done:
    mbedtls_ecp_point_free(&r);
    mbedtls_ecp_point_free(&p);
    mbedtls_mpi_free(&m);
    mbedtls_ecp_group_free(&grp);
    return err;
}

pt_err_t pt_es512_sign(const uint8_t d[PT_P521_LEN], const pt_iovec_t *msg, size_t n,
                       uint8_t sig[PT_ES512_SIG_LEN])
{
    if (d == NULL || sig == NULL) {
        return PT_ERR_INVALID;
    }
    if (g_rng == NULL) {
        return PT_ERR_STATE;
    }
    uint8_t hash[64];
    pt_err_t err = pt_hash(PT_HASH_SHA512, msg, n, hash);
    if (err != PT_OK) {
        return err;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi m;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&m);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    err = PT_ERR_CRYPTO;
    if (load_group(&grp) != 0) {
        goto done;
    }
    if (scalar_read(&grp, &m, d) != 0) {
        err = PT_ERR_INVALID;
        goto done;
    }
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    if (mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &m, hash, sizeof(hash), MBEDTLS_MD_SHA512,
                                   mbed_rng, NULL) != 0) {
        goto done;
    }
#else
    if (mbedtls_ecdsa_sign(&grp, &r, &s, &m, hash, sizeof(hash), mbed_rng, NULL) != 0) {
        goto done;
    }
#endif
    if (mbedtls_mpi_write_binary(&r, sig, PT_P521_LEN) != 0 ||
        mbedtls_mpi_write_binary(&s, sig + PT_P521_LEN, PT_P521_LEN) != 0) {
        goto done;
    }
    err = PT_OK;
done:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&m);
    mbedtls_ecp_group_free(&grp);
    pt_zeroize(hash, sizeof(hash));
    return err;
}

pt_err_t pt_es512_verify(const pt_p521_point_t *pub, const pt_iovec_t *msg, size_t n,
                         const uint8_t sig[PT_ES512_SIG_LEN])
{
    if (pub == NULL || sig == NULL) {
        return PT_ERR_INVALID;
    }
    uint8_t hash[64];
    pt_err_t err = pt_hash(PT_HASH_SHA512, msg, n, hash);
    if (err != PT_OK) {
        return err;
    }
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    err = PT_ERR_INVALID;
    if (load_group(&grp) == 0 && point_read(&grp, &q, pub) == 0 &&
        mbedtls_mpi_read_binary(&r, sig, PT_P521_LEN) == 0 &&
        mbedtls_mpi_read_binary(&s, sig + PT_P521_LEN, PT_P521_LEN) == 0 &&
        mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &q, &r, &s) == 0) {
        err = PT_OK;
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return err;
}
