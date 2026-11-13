# libFuzzer harnesses. Each new parser gets a target here.
function(pt_add_fuzzer name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE pt_core pt_warnings)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()
