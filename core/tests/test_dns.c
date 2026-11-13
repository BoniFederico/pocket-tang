#include "pt/pt_dns.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

static const uint8_t IP[4] = {192, 168, 4, 1};

/* Query for connectivitycheck.gstatic.com A IN, id 0x1234, RD set. */
static size_t make_query(uint8_t *q, uint16_t qtype)
{
    static const uint8_t hdr[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    static const uint8_t name[] = {17,  'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'v', 'i',
                                   't', 'y', 'c', 'h', 'e', 'c', 'k', 7,   'g', 's', 't',
                                   'a', 't', 'i', 'c', 3,   'c', 'o', 'm', 0};
    memcpy(q, hdr, sizeof(hdr));
    memcpy(q + sizeof(hdr), name, sizeof(name));
    size_t n = sizeof(hdr) + sizeof(name);
    q[n++] = (uint8_t)(qtype >> 8);
    q[n++] = (uint8_t)qtype;
    q[n++] = 0;
    q[n++] = 1;
    return n;
}

static void test_a_query_answered(void)
{
    uint8_t q[128];
    uint8_t r[PT_DNS_MAX];
    size_t n = make_query(q, 1);
    size_t m = pt_dns_answer(q, n, IP, r, sizeof(r));
    TEST_ASSERT_EQUAL(n + 16, m);
    TEST_ASSERT_EQUAL_HEX8(0x12, r[0]);
    TEST_ASSERT_EQUAL_HEX8(0x34, r[1]);
    TEST_ASSERT_EQUAL_HEX8(0x85, r[2]); /* QR | AA | RD */
    TEST_ASSERT_EQUAL_HEX8(0x00, r[3]); /* NOERROR */
    TEST_ASSERT_EQUAL(1, r[7]);         /* ANCOUNT */
    TEST_ASSERT_EQUAL_MEMORY(q + 12, r + 12, n - 12);
    TEST_ASSERT_EQUAL_HEX8(0xC0, r[n]);
    TEST_ASSERT_EQUAL_HEX8(0x0C, r[n + 1]);
    TEST_ASSERT_EQUAL_MEMORY(IP, r + m - 4, 4);
}

static void test_aaaa_gets_empty_answer(void)
{
    uint8_t q[128];
    uint8_t r[PT_DNS_MAX];
    size_t n = make_query(q, 28);
    size_t m = pt_dns_answer(q, n, IP, r, sizeof(r));
    TEST_ASSERT_EQUAL(n, m);
    TEST_ASSERT_EQUAL(0, r[7]);
    TEST_ASSERT_EQUAL_HEX8(0x00, r[3] & 0x0F);
}

static void test_ignored_and_errors(void)
{
    uint8_t q[128];
    uint8_t r[PT_DNS_MAX];
    size_t n = make_query(q, 1);
    TEST_ASSERT_EQUAL(0, pt_dns_answer(q, 11, IP, r, sizeof(r))); /* short header */
    q[2] |= 0x80;                                                 /* response bit */
    TEST_ASSERT_EQUAL(0, pt_dns_answer(q, n, IP, r, sizeof(r)));
    q[2] = 0x28; /* opcode UPDATE */
    TEST_ASSERT_EQUAL(12, pt_dns_answer(q, n, IP, r, sizeof(r)));
    TEST_ASSERT_EQUAL(4, r[3] & 0x0F); /* NOTIMP */
    n = make_query(q, 1);
    q[5] = 2; /* two questions */
    TEST_ASSERT_EQUAL(12, pt_dns_answer(q, n, IP, r, sizeof(r)));
    TEST_ASSERT_EQUAL(1, r[3] & 0x0F); /* FORMERR */
    n = make_query(q, 1);
    q[12] = 0xC0; /* compression pointer in question */
    memset(r, 0, sizeof(r));
    TEST_ASSERT_EQUAL(12, pt_dns_answer(q, n, IP, r, sizeof(r)));
    TEST_ASSERT_EQUAL(1, r[3] & 0x0F);
    n = make_query(q, 1);
    TEST_ASSERT_EQUAL(12, pt_dns_answer(q, n - 3, IP, r, sizeof(r))); /* truncated */
    q[12] = 100;                                                      /* label past the end */
    TEST_ASSERT_EQUAL(12, pt_dns_answer(q, n, IP, r, sizeof(r)));
    n = make_query(q, 1);
    TEST_ASSERT_EQUAL(0, pt_dns_answer(q, n, IP, r, n)); /* no room for answer */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_query_answered);
    RUN_TEST(test_aaaa_gets_empty_answer);
    RUN_TEST(test_ignored_and_errors);
    return UNITY_END();
}
