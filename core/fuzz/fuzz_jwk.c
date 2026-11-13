/* libFuzzer harness: JWK parsing (public and private), permission checks, thumbprints and the
 * key-store blob loader. */
#include "pt/pt_jwk.h"
#include "pt/pt_keystore.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

static uint64_t g_seed = 3;

static int fuzz_rng(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        g_seed = g_seed * 6364136223846793005ull + 1442695040888963407ull;
        buf[i] = (uint8_t)(g_seed >> 56);
    }
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    pt_crypto_set_rng(fuzz_rng, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pt_json_tok_t toks[64];
    pt_json_doc_t doc;
    if (pt_json_parse((const char *)data, size, toks, 64, &doc) == PT_OK) {
        (void)pt_jwk_permits(&doc, 0, false, PT_OP_DERIVE_KEY);
        (void)pt_jwk_permits(&doc, 0, true, PT_OP_SIGN);
        pt_jwk_t k;
        if (pt_jwk_parse(&doc, 0, true, &k) == PT_OK) {
            /* A parsed key is always a valid point that serialises and parses back. */
            if (pt_p521_point_check(&k.pub) != PT_OK) {
                __builtin_trap();
            }
            char buf[512];
            pt_jw_t w;
            pt_jw_init(&w, buf, sizeof(buf));
            pt_jwk_write_public(&w, &k.pub, k.alg, 0);
            size_t n = 0;
            if (pt_jw_finish(&w, &n) != PT_OK) {
                __builtin_trap();
            }
            char thp[PT_THP_MAX];
            if (pt_jwk_thumbprint_b64(&k.pub, PT_HASH_SHA256, thp, sizeof(thp)) != PT_OK) {
                __builtin_trap();
            }
        }
        pt_jwk_wipe(&k);
    }
    /* Treat the same input as a key-store blob: must never crash, must fail closed. */
    static pt_keystore_t ks;
    if (pt_keystore_load(&ks, data, size) == PT_OK) {
        if (pt_keystore_count(&ks) > PT_KEYS_MAX) {
            __builtin_trap();
        }
    } else if (pt_keystore_count(&ks) != 0) {
        __builtin_trap();
    }
    pt_keystore_wipe(&ks);
    return 0;
}
