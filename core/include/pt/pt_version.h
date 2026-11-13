/**
 * @file pt_version.h
 * @brief Firmware/library version information.
 */
#ifndef PT_VERSION_H
#define PT_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Semantic version of Pocket Tang, e.g. "1.0.0" or "1.0.0-dev". Release builds set it from the
 * git tag (environment variable PT_VERSION, see tools/fw-build.sh and CMakeLists.txt).
 */
#ifndef PT_VERSION
#define PT_VERSION "1.0.0-dev"
#endif

/**
 * @brief Return the version string.
 * @return NUL-terminated static string, never NULL.
 */
const char *pt_version(void);

#ifdef __cplusplus
}
#endif
#endif /* PT_VERSION_H */
