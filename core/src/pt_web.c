#include "pt/pt_web.h"
#include "pt/pt_b64url.h"
#include "pt/pt_crypto.h"

#include <string.h>

/* ------------------------------------------------------------------------------------------ */
/* Forms                                                                                       */
/* ------------------------------------------------------------------------------------------ */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Decode an urlencoded component; out may be NULL to only compare/validate. */
static pt_err_t decode(const char *in, size_t n, char *out, size_t cap, size_t *out_len)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '+') {
            c = ' ';
        } else if (c == '%') {
            if (i + 2 >= n) {
                return PT_ERR_INVALID;
            }
            int hi = hexval(in[i + 1]);
            int lo = hexval(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return PT_ERR_INVALID;
            }
            c = (unsigned char)(hi * 16 + lo);
            i += 2;
        }
        if (c == 0 || (c < 0x20 && c != '\t') || c == 0x7F) {
            return PT_ERR_INVALID;
        }
        if (out != NULL) {
            if (o + 1 >= cap) {
                return PT_ERR_NOSPACE;
            }
            out[o] = (char)c;
        }
        o++;
    }
    if (out != NULL) {
        out[o] = '\0';
    }
    if (out_len != NULL) {
        *out_len = o;
    }
    return PT_OK;
}

/* Compare an encoded key with a plain name. */
static bool key_matches(const char *k, size_t kn, const char *name)
{
    char tmp[64];
    size_t tl = 0;
    if (decode(k, kn, tmp, sizeof(tmp), &tl) != PT_OK) {
        return false;
    }
    return tl == strlen(name) && memcmp(tmp, name, tl) == 0;
}

pt_err_t pt_form_get(const char *body, size_t len, const char *name, char *out, size_t cap,
                     size_t *out_len)
{
    if (body == NULL || name == NULL || out == NULL || cap == 0) {
        return PT_ERR_INVALID;
    }
    if (len > PT_FORM_MAX) {
        return PT_ERR_LIMIT;
    }
    const char *val = NULL;
    size_t vlen = 0;
    size_t i = 0;
    while (i <= len) {
        size_t s = i;
        while (i < len && body[i] != '&') {
            i++;
        }
        size_t e = i; /* pair is body[s..e) */
        size_t eq = s;
        while (eq < e && body[eq] != '=') {
            eq++;
        }
        if (e > s && key_matches(body + s, eq - s, name)) {
            if (val != NULL) {
                return PT_ERR_INVALID; /* duplicate */
            }
            val = eq < e ? body + eq + 1 : body + e;
            vlen = eq < e ? e - eq - 1 : 0;
        }
        i++; /* skip '&' (or step past the end) */
    }
    if (val == NULL) {
        return PT_ERR_NOTFOUND;
    }
    return decode(val, vlen, out, cap, out_len);
}

pt_err_t pt_html_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    if (out == NULL || cap == 0) {
        return PT_ERR_NOSPACE;
    }
    for (; in != NULL && *in != '\0'; in++) {
        const char *rep = NULL;
        switch (*in) {
        case '&':
            rep = "&amp;";
            break;
        case '<':
            rep = "&lt;";
            break;
        case '>':
            rep = "&gt;";
            break;
        case '"':
            rep = "&quot;";
            break;
        case '\'':
            rep = "&#39;";
            break;
        default:
            break;
        }
        size_t n = rep ? strlen(rep) : 1;
        if (o + n + 1 > cap) {
            out[0] = '\0';
            return PT_ERR_NOSPACE;
        }
        if (rep) {
            memcpy(out + o, rep, n);
        } else {
            out[o] = *in;
        }
        o += n;
    }
    out[o] = '\0';
    return PT_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Passwords                                                                                   */
/* ------------------------------------------------------------------------------------------ */

bool pt_pw_acceptable(const char *pw, size_t len)
{
    if (pw == NULL || len < PT_PW_MIN || len > PT_PW_MAX) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)pw[i];
        if (c < 0x20 || c == 0x7F) {
            return false;
        }
    }
    return true;
}

pt_err_t pt_pw_set(pt_pw_t *v, const char *pw, size_t len, uint32_t iter)
{
    if (v == NULL || !pt_pw_acceptable(pw, len) || iter == 0) {
        return PT_ERR_INVALID;
    }
    pt_err_t err = pt_crypto_random(v->salt, sizeof(v->salt));
    if (err != PT_OK) {
        return err;
    }
    v->iter = iter;
    return pt_pbkdf2_sha256((const uint8_t *)pw, len, v->salt, sizeof(v->salt), iter, v->hash,
                            sizeof(v->hash));
}

bool pt_pw_check(const pt_pw_t *v, const char *pw, size_t len)
{
    if (v == NULL || pw == NULL || len > PT_PW_MAX || v->iter == 0) {
        return false;
    }
    uint8_t h[PT_PW_HASH_LEN];
    bool ok = pt_pbkdf2_sha256((const uint8_t *)pw, len, v->salt, sizeof(v->salt), v->iter, h,
                               sizeof(h)) == PT_OK &&
              pt_ct_memeq(h, v->hash, sizeof(h));
    pt_zeroize(h, sizeof(h));
    return ok;
}

/* ------------------------------------------------------------------------------------------ */
/* Sessions                                                                                    */
/* ------------------------------------------------------------------------------------------ */

pt_err_t pt_session_new(pt_session_t *s, uint32_t now, uint32_t ttl, char cookie[PT_TOKEN_B64],
                        char csrf[PT_TOKEN_B64])
{
    pt_session_end(s);
    pt_err_t err = pt_crypto_random(s->token, sizeof(s->token));
    if (err == PT_OK) {
        err = pt_crypto_random(s->csrf, sizeof(s->csrf));
    }
    if (err == PT_OK) {
        err = pt_b64url_encode(s->token, sizeof(s->token), cookie, PT_TOKEN_B64, NULL);
    }
    if (err == PT_OK) {
        err = pt_b64url_encode(s->csrf, sizeof(s->csrf), csrf, PT_TOKEN_B64, NULL);
    }
    if (err != PT_OK) {
        pt_session_end(s);
        return err;
    }
    s->expires = now + ttl;
    s->active = true;
    return PT_OK;
}

void pt_session_end(pt_session_t *s)
{
    pt_zeroize(s, sizeof(*s));
}

static bool token_eq(const uint8_t want[16], const char *b64, size_t len)
{
    uint8_t raw[16];
    if (len != PT_TOKEN_B64 - 1 || pt_b64url_decode_exact(b64, len, raw, sizeof(raw)) != PT_OK) {
        return false;
    }
    bool ok = pt_ct_memeq(raw, want, sizeof(raw));
    pt_zeroize(raw, sizeof(raw));
    return ok;
}

bool pt_session_check_cookie(const pt_session_t *s, const char *hdr, uint32_t now)
{
    if (s == NULL || !s->active || hdr == NULL || now >= s->expires) {
        return false;
    }
    /* Cookie: a=b; ptsid=XXXX; c=d  -- the session cookie must appear exactly once. */
    const size_t nl = strlen(PT_SESSION_COOKIE);
    const char *found = NULL;
    size_t found_len = 0;
    const char *p = hdr;
    while (*p != '\0') {
        while (*p == ' ' || *p == ';') {
            p++;
        }
        const char *start = p;
        while (*p != '\0' && *p != ';') {
            p++;
        }
        size_t n = (size_t)(p - start);
        if (n > nl && memcmp(start, PT_SESSION_COOKIE, nl) == 0 && start[nl] == '=') {
            if (found != NULL) {
                return false;
            }
            found = start + nl + 1;
            found_len = n - nl - 1;
            while (found_len > 0 && found[found_len - 1] == ' ') {
                found_len--;
            }
        }
    }
    return found != NULL && token_eq(s->token, found, found_len);
}

bool pt_session_check_csrf(const pt_session_t *s, const char *token, size_t len)
{
    return s != NULL && s->active && token != NULL && token_eq(s->csrf, token, len);
}

bool pt_ratelimit_allowed(const pt_ratelimit_t *r, uint32_t now)
{
    return now >= r->blocked_until;
}

void pt_ratelimit_fail(pt_ratelimit_t *r, uint32_t now)
{
    if (r->failures < 32) {
        r->failures++;
    }
    if (r->failures >= 3) {
        uint32_t shift = r->failures - 3;
        uint32_t delay = shift >= 9 ? 300u : (1u << shift);
        r->blocked_until = now + (delay > 300u ? 300u : delay);
    }
}

void pt_ratelimit_ok(pt_ratelimit_t *r)
{
    r->failures = 0;
    r->blocked_until = 0;
}
