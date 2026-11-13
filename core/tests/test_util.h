/* Shared helpers for host unit tests. */
#ifndef PT_TEST_UTIL_H
#define PT_TEST_UTIL_H

#include "pt/pt_crypto.h"
#include "pt/pt_json.h"
#include "pt/pt_jwk.h"

#include <stddef.h>

/** Register /dev/urandom as the core RNG. */
void tu_use_system_rng(void);

/** Register a deterministic (insecure, test-only) RNG seeded with @p seed. */
void tu_use_test_rng(unsigned seed);

/** Read a fixture file into a static buffer; returns NUL-terminated content and its length. */
const char *tu_read_fixture(const char *name, size_t *len);

/** Parse a JWK fixture (private allowed). Aborts the test on failure. */
void tu_load_jwk(const char *name, pt_jwk_t *out);

/** Extract a string member from a JSON text into @p out. Returns 0 on success. */
int tu_json_str(const char *json, size_t len, const char *member, char *out, size_t cap);

#endif
