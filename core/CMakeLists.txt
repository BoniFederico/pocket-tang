# Portable Pocket Tang core. No ESP-IDF, no FreeRTOS, no dynamic allocation in the request path.

# Host builds use upstream Mbed TLS at the same version ESP-IDF v5.5.6 bundles (see ADR-0001).
include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
    URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(mbedtls)

add_library(pt_core STATIC
    src/pt_version.c
    src/pt_common.c
    src/pt_b64url.c
    src/pt_json.c
    src/pt_jwk.c
    src/pt_keystore.c
    src/pt_tang.c
    src/pt_http.c
    src/pt_web.c
    net/pt_server.c
    crypto/mbedtls/pt_crypto_mbedtls.c
)
target_include_directories(pt_core PUBLIC include)
target_link_libraries(pt_core PRIVATE pt_warnings PUBLIC mbedcrypto)
# BSD socket extensions (MSG_DONTWAIT, TCP_NODELAY) for net/pt_server.c on glibc.
set_source_files_properties(net/pt_server.c PROPERTIES COMPILE_DEFINITIONS _DEFAULT_SOURCE)
target_compile_definitions(pt_core PUBLIC PT_CORE_HOST_BUILD=1)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
if(PT_FUZZ)
    add_subdirectory(fuzz)
endif()
