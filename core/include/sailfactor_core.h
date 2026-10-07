#ifndef SAILFACTOR_CORE_H
#define SAILFACTOR_CORE_H

/* C API of the SailFactor Rust core (core/src/ffi). */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SF_OK 0
#define SF_INVALID_ARGUMENT 1
#define SF_CORRUPTED 7
#define SF_LIMIT_EXCEEDED 8
#define SF_NOT_FOUND 9

/* Bytes owned by the core; release them with sf_string_free. */
typedef struct SfString {
    uint8_t *data;
    size_t length;
} SfString;

/* The core's version; a static string the caller must not free. */
const char *sf_core_version(void);

/* Wipes and releases a string from the core. Null strings are ignored. */
void sf_string_free(SfString string);

/*
 * Decodes the first readable QR code in a frame. One byte of brightness
 * per pixel: pixel_step bytes between pixels (1 to 4), row_stride bytes
 * between rows, width and height 1 to 4096. On SF_OK, out holds the UTF-8
 * payload of at most 2048 bytes; otherwise it is empty. SF_NOT_FOUND: no
 * code in the frame; SF_CORRUPTED: a code that could not be read;
 * SF_LIMIT_EXCEEDED: a payload over the limit.
 */
int32_t sf_qr_decode(const uint8_t *pixels, size_t length, uint32_t width, uint32_t height,
                     uint32_t row_stride, uint32_t pixel_step, SfString *out);

#ifdef __cplusplus
}
#endif

#endif /* SAILFACTOR_CORE_H */
