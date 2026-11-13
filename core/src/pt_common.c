#include "pt/pt_common.h"

bool pt_ct_memeq(const void *a, const void *b, size_t len)
{
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

void pt_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) {
        *p++ = 0;
    }
}

const char *pt_err_str(pt_err_t err)
{
    switch (err) {
    case PT_OK:
        return "ok";
    case PT_ERR_INVALID:
        return "invalid";
    case PT_ERR_NOSPACE:
        return "nospace";
    case PT_ERR_LIMIT:
        return "limit";
    case PT_ERR_NOTFOUND:
        return "notfound";
    case PT_ERR_DUPLICATE:
        return "duplicate";
    case PT_ERR_CRYPTO:
        return "crypto";
    case PT_ERR_FORBIDDEN:
        return "forbidden";
    case PT_ERR_STATE:
        return "state";
    case PT_ERR_UNSUPPORTED:
        return "unsupported";
    default:
        return "unknown";
    }
}
