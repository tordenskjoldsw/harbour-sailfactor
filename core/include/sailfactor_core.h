#ifndef SAILFACTOR_CORE_H
#define SAILFACTOR_CORE_H

/* C API of the SailFactor Rust core (core/src/ffi). */

#ifdef __cplusplus
extern "C" {
#endif

/* The core's version; a static string the caller must not free. */
const char *sf_core_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SAILFACTOR_CORE_H */
