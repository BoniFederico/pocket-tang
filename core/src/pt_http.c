#include "pt/pt_http.h"

#include <stdio.h>
#include <string.h>

static bool is_tchar(char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        return true;
    }
    return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static bool is_vchar_or_ws(unsigned char c)
{
    return c == ' ' || c == '\t' || (c >= 0x21 && c != 0x7F);
}

static unsigned char lower(char c)
{
    unsigned char u = (unsigned char)c;
    return (u >= 'A' && u <= 'Z') ? (unsigned char)(u | 0x20u) : u;
}

static bool name_eq(const char *a, size_t n, const char *lit)
{
    if (strlen(lit) != n) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (lower(a[i]) != (unsigned char)lit[i]) {
            return false;
        }
    }
    return true;
}

/* Case-insensitive search for a comma-separated token in a header value. */
static bool value_has_token(const char *v, size_t n, const char *tok)
{
    size_t tl = strlen(tok);
    size_t i = 0;
    while (i < n) {
        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) {
            i++;
        }
        size_t s = i;
        while (i < n && v[i] != ',' && v[i] != ' ' && v[i] != '\t') {
            i++;
        }
        if (i - s == tl) {
            bool eq = true;
            for (size_t k = 0; k < tl; k++) {
                eq = eq && lower(v[s + k]) == (unsigned char)tok[k];
            }
            if (eq) {
                return true;
            }
        }
    }
    return false;
}

int pt_http_parse_head(const char *buf, size_t len, size_t max_body, pt_http_req_t *req)
{
    memset(req, 0, sizeof(*req));
    /* Locate the end of the head. */
    size_t scan = len < PT_HTTP_MAX_HEAD ? len : PT_HTTP_MAX_HEAD;
    size_t end = 0;
    for (size_t i = 0; i + 3 < scan; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = i + 4;
            break;
        }
    }
    if (end == 0) {
        return len >= PT_HTTP_MAX_HEAD ? -431 : PT_HTTP_NEED_MORE;
    }
    req->head_len = end;

    /* Request line: method SP target SP HTTP/1.x CRLF */
    size_t i = 0;
    size_t m = 0;
    while (i < end && is_tchar(buf[i])) {
        if (m + 1 >= sizeof(req->method)) {
            return -400;
        }
        req->method[m++] = buf[i++];
    }
    if (m == 0 || buf[i] != ' ') {
        return -400;
    }
    i++;
    size_t ts = i;
    while (i < end && buf[i] != ' ') {
        unsigned char c = (unsigned char)buf[i];
        if (c <= 0x20 || c == 0x7F) {
            return -400;
        }
        i++;
    }
    size_t tl = i - ts;
    if (tl == 0 || buf[ts] != '/') {
        return -400; /* origin-form only */
    }
    if (tl > PT_HTTP_MAX_TARGET) {
        return -414;
    }
    req->target = buf + ts;
    req->target_len = tl;
    if (buf[i] != ' ') {
        return -400;
    }
    i++;
    if (end - i < 10 || memcmp(buf + i, "HTTP/1.", 7) != 0) {
        return -400;
    }
    char mv = buf[i + 7];
    if (mv != '0' && mv != '1') {
        return (mv >= '0' && mv <= '9') ? -505 : -400;
    }
    req->minor_version = mv - '0';
    req->keep_alive = req->minor_version == 1;
    i += 8;
    if (buf[i] != '\r' || buf[i + 1] != '\n') {
        return -400;
    }
    i += 2;

    /* Header fields */
    unsigned count = 0;
    bool seen_length = false;
    while (i < end - 2) {
        if (++count > PT_HTTP_MAX_HEADERS) {
            return -431;
        }
        size_t ns = i;
        while (i < end && is_tchar(buf[i])) {
            i++;
        }
        size_t nl = i - ns;
        if (nl == 0 || buf[i] != ':') {
            return -400; /* also rejects obs-fold and whitespace before the colon */
        }
        i++;
        while (buf[i] == ' ' || buf[i] == '\t') {
            i++;
        }
        size_t vs = i;
        while (i < end && buf[i] != '\r') {
            if (!is_vchar_or_ws((unsigned char)buf[i])) {
                return -400;
            }
            i++;
        }
        if (buf[i] != '\r' || buf[i + 1] != '\n') {
            return -400;
        }
        size_t ve = i;
        while (ve > vs && (buf[ve - 1] == ' ' || buf[ve - 1] == '\t')) {
            ve--;
        }
        i += 2;
        const char *name = buf + ns;
        const char *val = buf + vs;
        size_t vl = ve - vs;
        if (name_eq(name, nl, "content-length")) {
            /* cppcheck mis-tracks vl here (false positive); an empty value is covered by tests. */
            // cppcheck-suppress knownConditionTrueFalse
            if (seen_length || vl == 0 || vl > 9) {
                return -400;
            }
            size_t v = 0;
            for (size_t k = 0; k < vl; k++) {
                if (val[k] < '0' || val[k] > '9') {
                    return -400;
                }
                v = v * 10 + (size_t)(val[k] - '0');
            }
            seen_length = true;
            req->has_length = true;
            req->content_length = v;
        } else if (name_eq(name, nl, "transfer-encoding")) {
            return -501;
        } else if (name_eq(name, nl, "connection")) {
            if (value_has_token(val, vl, "close")) {
                req->keep_alive = false;
            } else if (value_has_token(val, vl, "keep-alive")) {
                req->keep_alive = true;
            }
        }
    }
    if (req->content_length > max_body) {
        return -413;
    }
    return 0;
}

const char *pt_http_reason(int status)
{
    switch (status) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 408:
        return "Request Timeout";
    case 413:
        return "Payload Too Large";
    case 414:
        return "URI Too Long";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 503:
        return "Service Unavailable";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "Unknown";
    }
}

size_t pt_http_write_head(char *out, size_t cap, int status, const char *content_type,
                          size_t content_length, bool keep_alive)
{
    int n;
    if (content_type != NULL) {
        n = snprintf(out, cap,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Connection: %s\r\n\r\n",
                     status, pt_http_reason(status), content_type, content_length,
                     keep_alive ? "keep-alive" : "close");
    } else {
        n = snprintf(out, cap, "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\nConnection: %s\r\n\r\n",
                     status, pt_http_reason(status), content_length,
                     keep_alive ? "keep-alive" : "close");
    }
    if (n < 0 || (size_t)n >= cap) {
        return 0;
    }
    return (size_t)n;
}
