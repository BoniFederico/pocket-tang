# Wraps the portable core (../../../core) as an ESP-IDF component. The core itself has no IDF includes.
set(PT_CORE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../core")
file(GLOB PT_CORE_SRCS "${PT_CORE_DIR}/src/*.c" "${PT_CORE_DIR}/crypto/mbedtls/*.c")
idf_component_register(
    SRCS ${PT_CORE_SRCS}
    INCLUDE_DIRS "${PT_CORE_DIR}/include"
    REQUIRES mbedtls)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wshadow -Wconversion -Wsign-conversion -Wvla)
