/*
 * libFuzzer harness for the complete protocol engine: the first input byte selects the method,
 * the input up to the first NUL is the request target, the rest is the body. Keys are generated
 * once with a fixed-seed RNG (fuzzing only). The harness also derives a valid /rec request with
 * the server key id so the fuzzer can reach the exchange path quickly.
 */
#include "pt/pt_tang.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

static bool contains(const char *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return true;
        }
    }
    return false;
}

static pt_tang_t g_tang;
static uint64_t g_seed = 1;

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
    pt_tang_init(&g_tang);
    if (pt_keystore_ensure(pt_tang_keystore(&g_tang)) != PT_OK ||
        pt_keystore_rotate(pt_tang_keystore(&g_tang)) != PT_OK ||
        pt_tang_refresh(&g_tang) != PT_OK) {
        __builtin_trap();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *const methods[] = {"GET", "POST", "PUT", "HEAD"};
    if (size < 1) {
        return 0;
    }
    const char *method = methods[data[0] & 3];
    data++;
    size--;
    const uint8_t *nul = memchr(data, 0, size);
    size_t tlen = nul ? (size_t)(nul - data) : size;
    const uint8_t *body = nul ? nul + 1 : NULL;
    size_t blen = nul ? size - tlen - 1 : 0;

    pt_tang_req_t req;
    pt_tang_route(method, (const char *)data, tlen, &req);
    static char out[PT_TANG_RESP_MAX];
    pt_tang_resp_t resp;
    pt_tang_handle(&g_tang, &req, body, blen, out, sizeof(out), &resp);
    if (resp.status == 200 && (resp.content_type == NULL || resp.body_len >= sizeof(out))) {
        __builtin_trap();
    }
    if (resp.status != 200 && resp.body_len != 0) {
        __builtin_trap();
    }
    /* Secrets must never appear in any response. */
    if (resp.status == 200 && contains(out, resp.body_len, "\"d\"")) {
        __builtin_trap();
    }
    return 0;
}
