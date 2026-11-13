/* libFuzzer harness: urlencoded form parser, HTML escaping and Cookie header validation. */
#include "pt/pt_web.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *const names[] = {"ssid", "pass", "host", "port", "csrf", "a"};
    char out[128];
    size_t n = 0;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (pt_form_get((const char *)data, size, names[i], out, sizeof(out), &n) == PT_OK) {
            if (n >= sizeof(out) || out[n] != '\0' || strlen(out) != n) {
                __builtin_trap(); /* decoded value never contains NUL */
            }
        }
    }
    /* NUL-terminated copy for the string-based helpers */
    char buf[512];
    size_t m = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, m);
    buf[m] = '\0';
    char esc[512 * 6 + 1];
    if (pt_html_escape(buf, esc, sizeof(esc)) != PT_OK || strpbrk(esc, "<>\"'") != NULL) {
        __builtin_trap();
    }
    pt_session_t s;
    memset(&s, 0, sizeof(s));
    s.active = true;
    s.expires = 100;
    memset(s.token, 0x41, sizeof(s.token));
    (void)pt_session_check_cookie(&s, buf, 1);
    (void)pt_session_check_csrf(&s, buf, m);
    return 0;
}
