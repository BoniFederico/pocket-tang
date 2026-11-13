# Host harness: a minimal POSIX HTTP front-end around the portable core, used for clevis interop
# tests and local development. Populated in milestone M1.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "host harness: skipped on ${CMAKE_SYSTEM_NAME}")
    return()
endif()
