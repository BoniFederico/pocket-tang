#include "pt/pt_json.h"
#include "pt/pt_b64url.h"

#include <string.h>

/* ------------------------------------------------------------------------------------------ */
/* Parser                                                                                     */
/* ------------------------------------------------------------------------------------------ */

enum state {
    ST_VALUE,        /* expecting a value (root, after ':' or after ',' in an array) */
    ST_VALUE_OR_END, /* just after '[' */
    ST_KEY_OR_END,   /* just after '{' */
    ST_KEY,          /* after ',' in an object */
    ST_COLON,        /* after a key */
    ST_COMMA_OR_END, /* after a value inside a container */
    ST_DONE          /* root value complete; only whitespace may follow */
};

struct parser {
    const char *buf;
    size_t len;
    size_t pos;
    pt_json_tok_t *toks;
    unsigned cap;
    unsigned count;
    int depth;
    int16_t stack[PT_JSON_MAX_DEPTH]; /* container token index per depth */
    int16_t key[PT_JSON_MAX_DEPTH];   /* pending key token per depth (objects) */
    enum state st;
    pt_err_t err;
};

static bool is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_hex(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int alloc_tok(struct parser *p, pt_json_type_t type, size_t start, int16_t parent)
{
    if (p->count >= p->cap) {
        p->err = PT_ERR_NOSPACE;
        return -1;
    }
    pt_json_tok_t *t = &p->toks[p->count];
    t->type = (uint16_t)type;
    t->size = 0;
    t->flags = 0;
    t->parent = parent;
    t->start = (uint32_t)start;
    t->end = (uint32_t)start;
    return (int)p->count++;
}

/* Parent for a new value: the pending key inside an object, the array itself, or -1 at root. */
static int16_t value_parent(const struct parser *p)
{
    if (p->depth == 0) {
        return -1;
    }
    int16_t c = p->stack[p->depth - 1];
    if (p->toks[c].type == PT_JSON_OBJECT) {
        return p->key[p->depth - 1];
    }
    return c;
}

/* Account a completed value in its container. */
static void attach_value(struct parser *p)
{
    if (p->depth == 0) {
        p->st = ST_DONE;
        return;
    }
    int16_t c = p->stack[p->depth - 1];
    if (p->toks[c].type == PT_JSON_OBJECT) {
        p->toks[p->key[p->depth - 1]].size = 1;
    }
    if (p->toks[c].size == UINT16_MAX) {
        p->err = PT_ERR_LIMIT;
        return;
    }
    p->toks[c].size++;
    p->st = ST_COMMA_OR_END;
}

/* Validate one UTF-8 encoded code point starting at buf[i]; return its length or 0. */
static size_t utf8_len(const unsigned char *s, size_t avail)
{
    unsigned char c = s[0];
    if (c < 0x80) {
        return 1;
    }
    if (c >= 0xC2 && c <= 0xDF) {
        return (avail >= 2 && (s[1] & 0xC0) == 0x80) ? 2 : 0;
    }
    if (c >= 0xE0 && c <= 0xEF) {
        if (avail < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) {
            return 0;
        }
        if (c == 0xE0 && s[1] < 0xA0) {
            return 0; /* overlong */
        }
        if (c == 0xED && s[1] >= 0xA0) {
            return 0; /* UTF-16 surrogate */
        }
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (avail < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) {
            return 0;
        }
        if (c == 0xF0 && s[1] < 0x90) {
            return 0; /* overlong */
        }
        if (c == 0xF4 && s[1] >= 0x90) {
            return 0; /* > U+10FFFF */
        }
        return 4;
    }
    return 0;
}

/* Scan a string starting at the opening quote; sets *end to the offset of the closing quote. */
static pt_err_t scan_string(struct parser *p, size_t *end, bool *escaped)
{
    size_t i = p->pos + 1;
    *escaped = false;
    while (i < p->len) {
        unsigned char c = (unsigned char)p->buf[i];
        if (c == '"') {
            *end = i;
            return PT_OK;
        }
        if (c == '\\') {
            *escaped = true;
            if (i + 1 >= p->len) {
                return PT_ERR_INVALID;
            }
            char e = p->buf[i + 1];
            switch (e) {
            case '"':
            case '\\':
            case '/':
            case 'b':
            case 'f':
            case 'n':
            case 'r':
            case 't':
                i += 2;
                break;
            case 'u':
                if (i + 5 >= p->len || !is_hex(p->buf[i + 2]) || !is_hex(p->buf[i + 3]) ||
                    !is_hex(p->buf[i + 4]) || !is_hex(p->buf[i + 5])) {
                    return PT_ERR_INVALID;
                }
                i += 6;
                break;
            default:
                return PT_ERR_INVALID;
            }
            continue;
        }
        if (c < 0x20) {
            return PT_ERR_INVALID; /* raw control character */
        }
        size_t n = utf8_len((const unsigned char *)p->buf + i, p->len - i);
        if (n == 0) {
            return PT_ERR_INVALID;
        }
        i += n;
    }
    return PT_ERR_INVALID; /* unterminated */
}

/* Strict RFC 8259 number: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? */
static pt_err_t scan_number(const struct parser *p, size_t *end)
{
    size_t i = p->pos;
    if (i < p->len && p->buf[i] == '-') {
        i++;
    }
    if (i >= p->len) {
        return PT_ERR_INVALID;
    }
    if (p->buf[i] == '0') {
        i++;
    } else if (p->buf[i] >= '1' && p->buf[i] <= '9') {
        while (i < p->len && is_digit(p->buf[i])) {
            i++;
        }
    } else {
        return PT_ERR_INVALID;
    }
    if (i < p->len && p->buf[i] == '.') {
        i++;
        if (i >= p->len || !is_digit(p->buf[i])) {
            return PT_ERR_INVALID;
        }
        while (i < p->len && is_digit(p->buf[i])) {
            i++;
        }
    }
    if (i < p->len && (p->buf[i] == 'e' || p->buf[i] == 'E')) {
        i++;
        if (i < p->len && (p->buf[i] == '+' || p->buf[i] == '-')) {
            i++;
        }
        if (i >= p->len || !is_digit(p->buf[i])) {
            return PT_ERR_INVALID;
        }
        while (i < p->len && is_digit(p->buf[i])) {
            i++;
        }
    }
    *end = i;
    return PT_OK;
}

static pt_err_t scan_literal(const struct parser *p, const char *lit, size_t *end)
{
    size_t n = strlen(lit);
    if (p->len - p->pos < n || memcmp(p->buf + p->pos, lit, n) != 0) {
        return PT_ERR_INVALID;
    }
    *end = p->pos + n;
    return PT_OK;
}

/* Parse one value at p->pos (any type). */
static void parse_value(struct parser *p)
{
    char c = p->buf[p->pos];
    int16_t parent = value_parent(p);
    if (c == '{' || c == '[') {
        if (p->depth >= PT_JSON_MAX_DEPTH) {
            p->err = PT_ERR_LIMIT;
            return;
        }
        int t = alloc_tok(p, c == '{' ? PT_JSON_OBJECT : PT_JSON_ARRAY, p->pos, parent);
        if (t < 0) {
            return;
        }
        p->stack[p->depth] = (int16_t)t;
        p->key[p->depth] = -1;
        p->depth++;
        p->pos++;
        p->st = (c == '{') ? ST_KEY_OR_END : ST_VALUE_OR_END;
        return;
    }
    size_t end = 0;
    if (c == '"') {
        bool escaped = false;
        p->err = scan_string(p, &end, &escaped);
        if (p->err != PT_OK) {
            return;
        }
        int t = alloc_tok(p, PT_JSON_STRING, p->pos + 1, parent);
        if (t < 0) {
            return;
        }
        p->toks[t].end = (uint32_t)end;
        if (escaped) {
            p->toks[t].flags |= PT_JSON_F_ESCAPED;
        }
        p->pos = end + 1;
        attach_value(p);
        return;
    }
    if (c == '-' || is_digit(c)) {
        p->err = scan_number(p, &end);
    } else if (c == 't') {
        p->err = scan_literal(p, "true", &end);
    } else if (c == 'f') {
        p->err = scan_literal(p, "false", &end);
    } else if (c == 'n') {
        p->err = scan_literal(p, "null", &end);
    } else {
        p->err = PT_ERR_INVALID;
    }
    if (p->err != PT_OK) {
        return;
    }
    /* A primitive must be followed by a structural character, whitespace or end of input. */
    if (end < p->len) {
        char n = p->buf[end];
        if (!(is_ws(n) || n == ',' || n == '}' || n == ']')) {
            p->err = PT_ERR_INVALID;
            return;
        }
    }
    int t = alloc_tok(p, PT_JSON_PRIMITIVE, p->pos, parent);
    if (t < 0) {
        return;
    }
    p->toks[t].end = (uint32_t)end;
    p->pos = end;
    attach_value(p);
}

static void parse_key(struct parser *p)
{
    if (p->buf[p->pos] != '"') {
        p->err = PT_ERR_INVALID;
        return;
    }
    size_t end = 0;
    bool escaped = false;
    p->err = scan_string(p, &end, &escaped);
    if (p->err != PT_OK) {
        return;
    }
    int t = alloc_tok(p, PT_JSON_STRING, p->pos + 1, p->stack[p->depth - 1]);
    if (t < 0) {
        return;
    }
    p->toks[t].end = (uint32_t)end;
    p->toks[t].flags |= PT_JSON_F_KEY | (escaped ? PT_JSON_F_ESCAPED : 0u);
    p->key[p->depth - 1] = (int16_t)t;
    p->pos = end + 1;
    p->st = ST_COLON;
}

static void close_container(struct parser *p, char c)
{
    int16_t t = p->stack[p->depth - 1];
    pt_json_type_t want = (c == '}') ? PT_JSON_OBJECT : PT_JSON_ARRAY;
    if (p->toks[t].type != want) {
        p->err = PT_ERR_INVALID;
        return;
    }
    p->toks[t].end = (uint32_t)(p->pos + 1);
    p->pos++;
    p->depth--;
    attach_value(p);
}

pt_err_t pt_json_parse(const char *buf, size_t len, pt_json_tok_t *toks, unsigned cap,
                       pt_json_doc_t *doc)
{
    if (buf == NULL || toks == NULL || doc == NULL || cap == 0 || cap > 32767) {
        return PT_ERR_INVALID;
    }
    if (len > PT_JSON_MAX_INPUT) {
        return PT_ERR_LIMIT;
    }
    struct parser p;
    memset(&p, 0, sizeof(p));
    p.buf = buf;
    p.len = len;
    p.toks = toks;
    p.cap = cap;
    p.st = ST_VALUE;

    while (p.err == PT_OK) {
        while (p.pos < p.len && is_ws(p.buf[p.pos])) {
            p.pos++;
        }
        if (p.pos >= p.len) {
            if (p.st != ST_DONE) {
                p.err = PT_ERR_INVALID;
            }
            break;
        }
        char c = p.buf[p.pos];
        switch (p.st) {
        case ST_VALUE:
            parse_value(&p);
            break;
        case ST_VALUE_OR_END:
            if (c == ']') {
                close_container(&p, c);
            } else {
                parse_value(&p);
            }
            break;
        case ST_KEY_OR_END:
            if (c == '}') {
                close_container(&p, c);
            } else {
                parse_key(&p);
            }
            break;
        case ST_KEY:
            parse_key(&p);
            break;
        case ST_COLON:
            if (c != ':') {
                p.err = PT_ERR_INVALID;
            } else {
                p.pos++;
                p.st = ST_VALUE;
            }
            break;
        case ST_COMMA_OR_END:
            if (c == ',') {
                p.pos++;
                p.st = (p.toks[p.stack[p.depth - 1]].type == PT_JSON_OBJECT) ? ST_KEY : ST_VALUE;
            } else if (c == '}' || c == ']') {
                close_container(&p, c);
            } else {
                p.err = PT_ERR_INVALID;
            }
            break;
        case ST_DONE: /* trailing garbage after the root value */
        default:
            p.err = PT_ERR_INVALID;
            break;
        }
    }
    if (p.err != PT_OK) {
        return p.err;
    }
    doc->buf = buf;
    doc->len = len;
    doc->toks = toks;
    doc->count = (int)p.count;
    return PT_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Navigation                                                                                 */
/* ------------------------------------------------------------------------------------------ */

static bool valid_idx(const pt_json_doc_t *doc, int tok)
{
    return doc != NULL && tok >= 0 && tok < doc->count;
}

pt_json_type_t pt_json_type(const pt_json_doc_t *doc, int tok)
{
    return valid_idx(doc, tok) ? (pt_json_type_t)doc->toks[tok].type : PT_JSON_UNDEF;
}

static bool is_descendant(const pt_json_doc_t *doc, int tok, int anc)
{
    int p = doc->toks[tok].parent;
    for (int guard = 0; p >= 0 && guard <= 2 * PT_JSON_MAX_DEPTH; guard++) {
        if (p == anc) {
            return true;
        }
        p = doc->toks[p].parent;
    }
    return false;
}

int pt_json_skip(const pt_json_doc_t *doc, int tok)
{
    if (!valid_idx(doc, tok)) {
        return doc ? doc->count : 0;
    }
    int j = tok + 1;
    while (j < doc->count && is_descendant(doc, j, tok)) {
        j++;
    }
    return j;
}

/* Decode a \uXXXX sequence at s (s points at the 4 hex digits). */
static uint32_t hex4(const char *s)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= (uint32_t)(c - 'a' + 10);
        } else {
            v |= (uint32_t)(c - 'A' + 10);
        }
    }
    return v;
}

static size_t put_utf8(uint32_t cp, char *out, size_t cap, size_t o)
{
    unsigned char tmp[4];
    size_t n;
    if (cp < 0x80) {
        tmp[0] = (unsigned char)cp;
        n = 1;
    } else if (cp < 0x800) {
        tmp[0] = (unsigned char)(0xC0 | (cp >> 6));
        tmp[1] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        tmp[0] = (unsigned char)(0xE0 | (cp >> 12));
        tmp[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        tmp[0] = (unsigned char)(0xF0 | (cp >> 18));
        tmp[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        tmp[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[3] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    if (o + n > cap) {
        return SIZE_MAX;
    }
    memcpy(out + o, tmp, n);
    return o + n;
}

pt_err_t pt_json_str_get(const pt_json_doc_t *doc, int tok, char *out, size_t cap, size_t *out_len)
{
    if (!valid_idx(doc, tok) || doc->toks[tok].type != PT_JSON_STRING || out == NULL || cap == 0) {
        return PT_ERR_INVALID;
    }
    const pt_json_tok_t *t = &doc->toks[tok];
    const char *s = doc->buf + t->start;
    size_t n = t->end - t->start;
    size_t o = 0;
    if ((t->flags & PT_JSON_F_ESCAPED) == 0) {
        if (n + 1 > cap) {
            return PT_ERR_NOSPACE;
        }
        memcpy(out, s, n);
        out[n] = '\0';
        if (out_len) {
            *out_len = n;
        }
        return PT_OK;
    }
    for (size_t i = 0; i < n;) {
        char c = s[i];
        if (c != '\\') {
            if (o + 1 >= cap) {
                return PT_ERR_NOSPACE;
            }
            out[o++] = c;
            i++;
            continue;
        }
        /* The scanner guaranteed the escape is well formed and in range. */
        char e = s[i + 1];
        char r = 0;
        switch (e) {
        case '"':
            r = '"';
            break;
        case '\\':
            r = '\\';
            break;
        case '/':
            r = '/';
            break;
        case 'b':
            r = '\b';
            break;
        case 'f':
            r = '\f';
            break;
        case 'n':
            r = '\n';
            break;
        case 'r':
            r = '\r';
            break;
        case 't':
            r = '\t';
            break;
        case 'u': {
            uint32_t cp = hex4(s + i + 2);
            i += 6;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                /* high surrogate: a low surrogate escape must follow */
                if (i + 6 > n || s[i] != '\\' || s[i + 1] != 'u') {
                    return PT_ERR_INVALID;
                }
                uint32_t lo = hex4(s + i + 2);
                if (lo < 0xDC00 || lo > 0xDFFF) {
                    return PT_ERR_INVALID;
                }
                i += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                return PT_ERR_INVALID; /* lone low surrogate */
            }
            /* reserve one byte for the NUL */
            o = put_utf8(cp, out, cap - 1, o);
            if (o == SIZE_MAX) {
                return PT_ERR_NOSPACE;
            }
            continue;
        }
        default:
            return PT_ERR_INVALID;
        }
        if (o + 1 >= cap) {
            return PT_ERR_NOSPACE;
        }
        out[o++] = r;
        i += 2;
    }
    out[o] = '\0';
    if (out_len) {
        *out_len = o;
    }
    return PT_OK;
}

bool pt_json_str_eq(const pt_json_doc_t *doc, int tok, const char *lit)
{
    if (!valid_idx(doc, tok) || doc->toks[tok].type != PT_JSON_STRING || lit == NULL) {
        return false;
    }
    const pt_json_tok_t *t = &doc->toks[tok];
    size_t n = t->end - t->start;
    size_t ln = strlen(lit);
    if ((t->flags & PT_JSON_F_ESCAPED) == 0) {
        return n == ln && memcmp(doc->buf + t->start, lit, n) == 0;
    }
    char tmp[128];
    size_t got = 0;
    if (pt_json_str_get(doc, tok, tmp, sizeof(tmp), &got) != PT_OK) {
        return false;
    }
    return got == ln && memcmp(tmp, lit, ln) == 0;
}

int pt_json_obj_get(const pt_json_doc_t *doc, int obj, const char *key)
{
    if (!valid_idx(doc, obj) || doc->toks[obj].type != PT_JSON_OBJECT || key == NULL) {
        return -(int)PT_ERR_INVALID;
    }
    int found = -1;
    int i = obj + 1;
    for (uint16_t m = 0; m < doc->toks[obj].size && i < doc->count; m++) {
        /* i is a key token; its value is i + 1 */
        if (pt_json_str_eq(doc, i, key)) {
            if (found >= 0) {
                return -(int)PT_ERR_DUPLICATE;
            }
            found = i + 1;
        }
        i = pt_json_skip(doc, i + 1);
    }
    return found >= 0 ? found : -(int)PT_ERR_NOTFOUND;
}

int pt_json_arr_get(const pt_json_doc_t *doc, int arr, unsigned idx)
{
    if (!valid_idx(doc, arr) || doc->toks[arr].type != PT_JSON_ARRAY) {
        return -(int)PT_ERR_INVALID;
    }
    if (idx >= doc->toks[arr].size) {
        return -(int)PT_ERR_NOTFOUND;
    }
    int i = arr + 1;
    for (unsigned k = 0; k < idx; k++) {
        i = pt_json_skip(doc, i);
    }
    return i;
}

bool pt_json_arr_has_str(const pt_json_doc_t *doc, int arr, const char *lit)
{
    if (!valid_idx(doc, arr) || doc->toks[arr].type != PT_JSON_ARRAY) {
        return false;
    }
    int i = arr + 1;
    for (uint16_t k = 0; k < doc->toks[arr].size && i < doc->count; k++) {
        if (pt_json_str_eq(doc, i, lit)) {
            return true;
        }
        i = pt_json_skip(doc, i);
    }
    return false;
}

/* ------------------------------------------------------------------------------------------ */
/* Writer                                                                                     */
/* ------------------------------------------------------------------------------------------ */

static void jw_putc(pt_jw_t *w, char c)
{
    if (w->err != PT_OK) {
        return;
    }
    if (w->len + 1 >= w->cap) { /* keep room for the NUL */
        w->err = PT_ERR_NOSPACE;
        return;
    }
    w->buf[w->len++] = c;
}

static void jw_puts(pt_jw_t *w, const char *s, size_t n)
{
    if (w->err != PT_OK) {
        return;
    }
    if (w->len + n + 1 > w->cap) {
        w->err = PT_ERR_NOSPACE;
        return;
    }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
}

/* Emit the separator before a value (or key). */
static void jw_prefix(pt_jw_t *w)
{
    if (w->pending_key) {
        w->pending_key = 0;
        return;
    }
    if (w->depth > 0) {
        if (!w->first[w->depth]) {
            jw_putc(w, ',');
        }
        w->first[w->depth] = 0;
    } else {
        /* Only one root value is allowed. */
        if (!w->first[0]) {
            w->err = PT_ERR_STATE;
        }
        w->first[0] = 0;
    }
}

static void jw_quoted(pt_jw_t *w, const char *s, size_t n)
{
    static const char HEX[] = "0123456789abcdef";
    jw_putc(w, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"') {
            jw_puts(w, "\\\"", 2);
        } else if (c == '\\') {
            jw_puts(w, "\\\\", 2);
        } else if (c < 0x20) {
            const char esc[6] = {'\\', 'u', '0', '0', HEX[c >> 4], HEX[c & 15]};
            if (c == '\n') {
                jw_puts(w, "\\n", 2);
            } else if (c == '\r') {
                jw_puts(w, "\\r", 2);
            } else if (c == '\t') {
                jw_puts(w, "\\t", 2);
            } else {
                jw_puts(w, esc, 6);
            }
        } else {
            jw_putc(w, (char)c);
        }
    }
    jw_putc(w, '"');
}

void pt_jw_init(pt_jw_t *w, char *buf, size_t cap)
{
    memset(w, 0, sizeof(*w));
    w->buf = buf;
    w->cap = cap;
    w->first[0] = 1;
    if (buf == NULL || cap == 0) {
        w->err = PT_ERR_NOSPACE;
    }
}

static void jw_open(pt_jw_t *w, char c)
{
    jw_prefix(w);
    if (w->depth >= PT_JSON_MAX_DEPTH) {
        w->err = PT_ERR_LIMIT;
        return;
    }
    jw_putc(w, c);
    w->depth++;
    w->first[w->depth] = 1;
}

static void jw_close(pt_jw_t *w, char c)
{
    if (w->depth == 0 || w->pending_key) {
        w->err = PT_ERR_STATE;
        return;
    }
    jw_putc(w, c);
    w->depth--;
}

void pt_jw_obj_begin(pt_jw_t *w)
{
    jw_open(w, '{');
}

void pt_jw_obj_end(pt_jw_t *w)
{
    jw_close(w, '}');
}

void pt_jw_arr_begin(pt_jw_t *w)
{
    jw_open(w, '[');
}

void pt_jw_arr_end(pt_jw_t *w)
{
    jw_close(w, ']');
}

void pt_jw_key(pt_jw_t *w, const char *key)
{
    if (w->depth == 0 || w->pending_key) {
        w->err = PT_ERR_STATE;
        return;
    }
    jw_prefix(w);
    jw_quoted(w, key, strlen(key));
    jw_putc(w, ':');
    w->pending_key = 1;
}

void pt_jw_strn(pt_jw_t *w, const char *s, size_t n)
{
    jw_prefix(w);
    jw_quoted(w, s, n);
}

void pt_jw_str(pt_jw_t *w, const char *s)
{
    pt_jw_strn(w, s, strlen(s));
}

void pt_jw_raw(pt_jw_t *w, const char *json, size_t n)
{
    jw_prefix(w);
    jw_puts(w, json, n);
}

void pt_jw_b64url(pt_jw_t *w, const uint8_t *data, size_t n)
{
    jw_prefix(w);
    if (w->err != PT_OK) {
        return;
    }
    size_t need = PT_B64URL_ENC_LEN(n);
    if (w->len + need + 3 > w->cap) {
        w->err = PT_ERR_NOSPACE;
        return;
    }
    w->buf[w->len++] = '"';
    size_t wrote = 0;
    if (pt_b64url_encode(data, n, w->buf + w->len, w->cap - w->len, &wrote) != PT_OK) {
        w->err = PT_ERR_NOSPACE;
        return;
    }
    w->len += wrote;
    w->buf[w->len++] = '"';
}

void pt_jw_uint(pt_jw_t *w, uint32_t v)
{
    char tmp[11];
    size_t n = 0;
    do {
        tmp[sizeof(tmp) - 1 - n] = (char)('0' + (v % 10));
        v /= 10;
        n++;
    } while (v != 0 && n < sizeof(tmp));
    jw_prefix(w);
    jw_puts(w, tmp + sizeof(tmp) - n, n);
}

void pt_jw_bool(pt_jw_t *w, bool v)
{
    jw_prefix(w);
    if (v) {
        jw_puts(w, "true", 4);
    } else {
        jw_puts(w, "false", 5);
    }
}

void pt_jw_null(pt_jw_t *w)
{
    jw_prefix(w);
    jw_puts(w, "null", 4);
}

pt_err_t pt_jw_finish(pt_jw_t *w, size_t *len)
{
    if (w->err == PT_OK && (w->depth != 0 || w->pending_key || w->first[0])) {
        w->err = PT_ERR_STATE;
    }
    if (w->buf != NULL && w->cap > 0) {
        w->buf[w->len < w->cap ? w->len : w->cap - 1] = '\0';
    }
    if (len) {
        *len = w->len;
    }
    return w->err;
}
