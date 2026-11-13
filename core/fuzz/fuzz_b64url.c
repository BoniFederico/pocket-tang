/* libFuzzer harness: base64url decode must accept exactly the canonical encodings. */
#include "pt/pt_b64url.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t dec[2048];
    char enc[4096];
    size_t dl = 0;
    size_t el = 0;
    if (size > 2048) {
        return 0;
    }
    if (pt_b64url_decode((const char *)data, size, dec, sizeof(dec), &dl) == PT_OK) {
        /* decode(x) ok => encode(decode(x)) == x (canonical form) */
        if (pt_b64url_encode(dec, dl, enc, sizeof(enc), &el) != PT_OK || el != size ||
            memcmp(enc, data, size) != 0) {
            __builtin_trap();
        }
    }
    /* encode(x) always round-trips */
    if (pt_b64url_encode(data, size, enc, sizeof(enc), &el) != PT_OK) {
        __builtin_trap();
    }
    if (pt_b64url_decode(enc, el, dec, sizeof(dec), &dl) != PT_OK || dl != size ||
        (size && memcmp(dec, data, size) != 0)) {
        __builtin_trap();
    }
    return 0;
}
