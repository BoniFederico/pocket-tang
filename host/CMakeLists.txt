# Host harness: a minimal POSIX HTTP front-end around the portable core, used for clevis interop
# tests and local development. Populated in milestone M1.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "host harness: skipped on ${CMAKE_SYSTEM_NAME}")
    return()
endif()

add_executable(tangd-host tangd_host.c)
target_link_libraries(tangd-host PRIVATE pt_core pt_warnings)
# getrandom(), sigaction() and friends are not part of strict C17.
target_compile_definitions(tangd-host PRIVATE _GNU_SOURCE)
