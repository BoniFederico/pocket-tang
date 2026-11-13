/**
 * @file pt_dns.h
 * @brief Minimal captive-portal DNS responder logic (RFC 1035 subset).
 *
 * In setup mode the device answers every A query with its own access-point address, which makes
 * phones and laptops open the setup page automatically. The parser accepts only standard
 * queries with exactly one question, uncompressed names of at most 255 bytes and bounded labels;
 * anything else is ignored (no answer) or answered with an error code.
 */
#ifndef PT_DNS_H
#define PT_DNS_H

#include "pt/pt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Largest DNS message we accept or produce over UDP. */
#define PT_DNS_MAX 512

/**
 * @brief Build the response to a DNS query.
 *
 * - A/IN (or ANY) question: one A record pointing to @p ipv4 (TTL 60 s).
 * - Other types (AAAA, ...): NOERROR with no answers, so clients fall back to IPv4.
 * - Non-query opcodes: NOTIMP. Malformed questions: FORMERR when the header is readable.
 *
 * @param query  received datagram
 * @param qlen   its length
 * @param ipv4   address to answer with (network byte order bytes)
 * @param out    response buffer (at least PT_DNS_MAX bytes recommended)
 * @param cap    capacity of @p out
 * @return length of the response, or 0 if the datagram must be ignored (not a query, truncated
 *         header, response bit set, ...).
 */
size_t pt_dns_answer(const uint8_t *query, size_t qlen, const uint8_t ipv4[4], uint8_t *out,
                     size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* PT_DNS_H */
