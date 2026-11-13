/* libFuzzer harness: HTTP request-head parser. */
#include "pt/pt_http.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pt_http_req_t req;
    int rc = pt_http_parse_head((const char *)data, size, 2048, &req);
    if (rc == 0) {
        /* Invariants of a successful parse. */
        if (req.head_len > size || req.head_len > PT_HTTP_MAX_HEAD || req.target_len == 0 ||
            req.target_len > PT_HTTP_MAX_TARGET || req.target < (const char *)data ||
            req.target + req.target_len > (const char *)data + req.head_len ||
            req.content_length > 2048 || req.method[0] == '\0' ||
            (req.minor_version != 0 && req.minor_version != 1)) {
            __builtin_trap();
        }
    } else if (rc != PT_HTTP_NEED_MORE && rc >= 0) {
        __builtin_trap();
    }
    return 0;
}
