# Portable Pocket Tang core. No ESP-IDF, no FreeRTOS, no dynamic allocation in the request path.
add_library(pt_core STATIC
    src/pt_version.c
)
target_include_directories(pt_core PUBLIC include)
target_link_libraries(pt_core PRIVATE pt_warnings)
target_compile_definitions(pt_core PUBLIC PT_CORE_HOST_BUILD=1)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
if(PT_FUZZ)
    add_subdirectory(fuzz)
endif()
