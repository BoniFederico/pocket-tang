#include "pt/pt_dns.h"

#include <string.h>

#define HDR           12
#define FLAG_QR       0x8000u
#define OPCODE_MASK   0x7800u
#define FLAG_RD       0x0100u
#define RCODE_FORMERR 1u
#define RCODE_NOTIMP  4u
#define TYPE_A        1u
#define TYPE_ANY      255u
#define CLASS_IN      1u

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Header-only error response. */
static size_t error_reply(const uint8_t *q, uint16_t flags, unsigned rcode, uint8_t *out,
                          size_t cap)
{
    if (cap < HDR) {
        return 0;
    }
    memcpy(out, q, 2); /* id */
    wr16(out + 2, (uint16_t)(FLAG_QR | (flags & (OPCODE_MASK | FLAG_RD)) | rcode));
    memset(out + 4, 0, HDR - 4);
    return HDR;
}

size_t pt_dns_answer(const uint8_t *query, size_t qlen, const uint8_t ipv4[4], uint8_t *out,
                     size_t cap)
{
    if (query == NULL || out == NULL || ipv4 == NULL || qlen < HDR || qlen > PT_DNS_MAX) {
        return 0;
    }
    uint16_t flags = rd16(query + 2);
    if (flags & FLAG_QR) {
        return 0; /* a response: never answer (avoids loops) */
    }
    if ((flags & OPCODE_MASK) != 0) {
        return error_reply(query, flags, RCODE_NOTIMP, out, cap);
    }
    if (rd16(query + 4) != 1 || rd16(query + 6) != 0 || rd16(query + 8) != 0) {
        return error_reply(query, flags, RCODE_FORMERR, out, cap);
    }
    /* Walk the question name: labels of 1..63 bytes, total <= 255, no compression. */
    size_t i = HDR;
    size_t total = 0;
    for (;;) {
        if (i >= qlen) {
            return error_reply(query, flags, RCODE_FORMERR, out, cap);
        }
        uint8_t l = query[i];
        if (l == 0) {
            i++;
            break;
        }
        if (l > 63) {
            return error_reply(query, flags, RCODE_FORMERR, out, cap);
        }
        total += (size_t)l + 1;
        if (total > 255 || i + 1 + l > qlen) {
            return error_reply(query, flags, RCODE_FORMERR, out, cap);
        }
        i += 1 + (size_t)l;
    }
    if (i + 4 > qlen) {
        return error_reply(query, flags, RCODE_FORMERR, out, cap);
    }
    uint16_t qtype = rd16(query + i);
    uint16_t qclass = rd16(query + i + 2);
    size_t qend = i + 4; /* end of the question section (additional records are ignored) */
    bool answer = (qtype == TYPE_A || qtype == TYPE_ANY) && qclass == CLASS_IN;
    size_t need = qend + (answer ? 16 : 0);
    if (cap < need) {
        return 0;
    }
    memcpy(out, query, qend);
    wr16(out + 2, (uint16_t)(FLAG_QR | 0x0400u /* AA */ | (flags & FLAG_RD)));
    wr16(out + 4, 1);
    wr16(out + 6, answer ? 1 : 0);
    wr16(out + 8, 0);
    wr16(out + 10, 0);
    if (answer) {
        uint8_t *a = out + qend;
        wr16(a, 0xC00Cu); /* pointer to the question name */
        wr16(a + 2, TYPE_A);
        wr16(a + 4, CLASS_IN);
        a[6] = 0;
        a[7] = 0;
        wr16(a + 8, 60); /* TTL */
        wr16(a + 10, 4);
        memcpy(a + 12, ipv4, 4);
    }
    return need;
}
