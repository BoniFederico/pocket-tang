# Host build: portable core, host HTTP harness, unit tests and fuzzers.
# The firmware is a separate ESP-IDF project under firmware/.
cmake_minimum_required(VERSION 3.22)
project(pocket_tang C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PT_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(PT_COVERAGE "Build with coverage instrumentation" OFF)
option(PT_FUZZ "Build libFuzzer targets (requires clang)" OFF)
option(PT_WERROR "Treat warnings as errors" ON)

add_library(pt_warnings INTERFACE)
target_compile_options(pt_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual
    -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes -Wvla
    -fno-common -fstack-protector-strong
    $<$<BOOL:${PT_WERROR}>:-Werror>)

if(PT_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
endif()
if(PT_COVERAGE)
    add_compile_options(--coverage -O0)
    add_link_options(--coverage)
endif()
if(PT_FUZZ)
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

include(CTest)
add_subdirectory(core)
add_subdirectory(host)
