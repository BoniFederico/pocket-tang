#include "pt/pt_b64url.h"

static const char ALPHABET[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Decode one character; returns 0..63 or 0xFF for invalid. */
static uint8_t decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (uint8_t)(c - 'A');
    }
    if (c >= 'a' && c <= 'z') {
        return (uint8_t)(c - 'a' + 26);
    }
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0' + 52);
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
        return 63;
    }
    return 0xFF;
}

bool pt_b64url_is_char(char c)
{
    return decode_char(c) != 0xFF;
}

pt_err_t pt_b64url_encode(const uint8_t *in, size_t in_len, char *out, size_t cap, size_t *out_len)
{
    size_t need = PT_B64URL_ENC_LEN(in_len);
    if (cap < need + 1) {
        return PT_ERR_NOSPACE;
    }
    size_t o = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = ALPHABET[(v >> 6) & 63];
        out[o++] = ALPHABET[v & 63];
        i += 3;
    }
    if (in_len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
    } else if (in_len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = ALPHABET[(v >> 6) & 63];
    }
    out[o] = '\0';
    if (out_len) {
        *out_len = o;
    }
    return PT_OK;
}

pt_err_t pt_b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t rem = in_len % 4;
    if (rem == 1) {
        return PT_ERR_INVALID;
    }
    size_t need = (in_len / 4) * 3 + (rem == 2 ? 1 : rem == 3 ? 2 : 0);
    if (cap < need) {
        return PT_ERR_NOSPACE;
    }
    size_t o = 0;
    size_t i = 0;
    while (i + 4 <= in_len) {
        uint8_t a = decode_char(in[i]);
        uint8_t b = decode_char(in[i + 1]);
        uint8_t c = decode_char(in[i + 2]);
        uint8_t d = decode_char(in[i + 3]);
        if ((a | b | c | d) == 0xFF) {
            return PT_ERR_INVALID;
        }
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | d;
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
        out[o++] = (uint8_t)v;
        i += 4;
    }
    if (rem == 2) {
        uint8_t a = decode_char(in[i]);
        uint8_t b = decode_char(in[i + 1]);
        if ((a | b) == 0xFF || (b & 0x0F) != 0) {
            return PT_ERR_INVALID; /* non-canonical trailing bits */
        }
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
    } else if (rem == 3) {
        uint8_t a = decode_char(in[i]);
        uint8_t b = decode_char(in[i + 1]);
        uint8_t c = decode_char(in[i + 2]);
        if ((a | b | c) == 0xFF || (c & 0x03) != 0) {
            return PT_ERR_INVALID;
        }
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        out[o++] = (uint8_t)((b << 4) | (c >> 2));
    }
    *out_len = o;
    return PT_OK;
}

pt_err_t pt_b64url_decode_exact(const char *in, size_t in_len, uint8_t *out, size_t want)
{
    size_t got = 0;
    pt_err_t err = pt_b64url_decode(in, in_len, out, want, &got);
    if (err == PT_ERR_NOSPACE) {
        return PT_ERR_INVALID;
    }
    if (err != PT_OK) {
        return err;
    }
    return got == want ? PT_OK : PT_ERR_INVALID;
}
