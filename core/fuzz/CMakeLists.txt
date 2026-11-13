# libFuzzer harnesses. Each new parser gets a target here.
function(pt_add_fuzzer name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE pt_core pt_warnings)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()

pt_add_fuzzer(fuzz_json fuzz_json.c)
pt_add_fuzzer(fuzz_b64url fuzz_b64url.c)
pt_add_fuzzer(fuzz_jwk fuzz_jwk.c)
pt_add_fuzzer(fuzz_tang fuzz_tang.c)
pt_add_fuzzer(fuzz_http fuzz_http.c)
pt_add_fuzzer(fuzz_web fuzz_web.c)
