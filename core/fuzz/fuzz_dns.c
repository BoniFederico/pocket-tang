/* libFuzzer harness: captive-portal DNS responder. */
#include "pt/pt_dns.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t ip[4] = {192, 168, 4, 1};
    uint8_t out[PT_DNS_MAX];
    size_t n = pt_dns_answer(data, size, ip, out, sizeof(out));
    if (n > sizeof(out) || (n != 0 && n < 12)) {
        __builtin_trap();
    }
    if (n >= 12 && ((out[2] & 0x80) == 0 || memcmp(out, data, 2) != 0)) {
        __builtin_trap(); /* every reply is a response with the query id */
    }
    /* small output buffers must never overflow */
    uint8_t tiny[20];
    if (pt_dns_answer(data, size, ip, tiny, sizeof(tiny)) > sizeof(tiny)) {
        __builtin_trap();
    }
    return 0;
}
