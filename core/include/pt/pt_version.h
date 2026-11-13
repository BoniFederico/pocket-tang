/**
 * @file pt_version.h
 * @brief Firmware/library version information.
 */
#ifndef PT_VERSION_H
#define PT_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

/** Semantic version of Pocket Tang, e.g. "1.0.0" or "1.0.0-dev+abc1234". */
#define PT_VERSION "0.1.0-dev"

/**
 * @brief Return the version string.
 * @return NUL-terminated static string, never NULL.
 */
const char *pt_version(void);

#ifdef __cplusplus
}
#endif
#endif /* PT_VERSION_H */
