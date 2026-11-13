include(FetchContent)
FetchContent_Declare(unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG v2.6.1
    GIT_SHALLOW TRUE)
set(UNITY_EXTENSION_FIXTURE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(unity)
target_compile_definitions(unity PUBLIC UNITY_INCLUDE_DOUBLE UNITY_OUTPUT_COLOR)

function(pt_add_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE pt_core unity pt_warnings)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

pt_add_test(test_version test_version.c)
