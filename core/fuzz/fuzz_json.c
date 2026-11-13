/* libFuzzer harness: strict JSON parser plus navigation helpers and the unescape path. */
#include "pt/pt_json.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pt_json_tok_t toks[96];
    pt_json_doc_t doc;
    if (pt_json_parse((const char *)data, size, toks, 96, &doc) != PT_OK) {
        return 0;
    }
    /* Walk every token and exercise the helpers. */
    char tmp[256];
    size_t n;
    for (int i = 0; i < doc.count; i++) {
        pt_json_type_t t = pt_json_type(&doc, i);
        if (t == PT_JSON_STRING) {
            (void)pt_json_str_get(&doc, i, tmp, sizeof(tmp), &n);
            (void)pt_json_str_eq(&doc, i, "kty");
        } else if (t == PT_JSON_OBJECT) {
            (void)pt_json_obj_get(&doc, i, "kty");
            (void)pt_json_obj_get(&doc, i, "x");
        } else if (t == PT_JSON_ARRAY) {
            (void)pt_json_arr_has_str(&doc, i, "deriveKey");
            (void)pt_json_arr_get(&doc, i, 0);
            (void)pt_json_arr_get(&doc, i, 3);
        }
        int next = pt_json_skip(&doc, i);
        if (next <= i || next > doc.count) {
            __builtin_trap();
        }
    }
    /* Re-serialise strings through the writer; the result must parse again. */
    char out[1024];
    pt_jw_t w;
    pt_jw_init(&w, out, sizeof(out));
    pt_jw_arr_begin(&w);
    for (int i = 0; i < doc.count; i++) {
        if (pt_json_type(&doc, i) == PT_JSON_STRING &&
            pt_json_str_get(&doc, i, tmp, sizeof(tmp), &n) == PT_OK) {
            pt_jw_strn(&w, tmp, n);
        }
    }
    pt_jw_arr_end(&w);
    size_t len = 0;
    if (pt_jw_finish(&w, &len) == PT_OK) {
        pt_json_tok_t toks2[96];
        pt_json_doc_t doc2;
        if (pt_json_parse(out, len, toks2, 96, &doc2) != PT_OK) {
            __builtin_trap();
        }
    }
    return 0;
}
