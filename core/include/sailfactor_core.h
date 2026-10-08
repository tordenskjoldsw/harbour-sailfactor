#ifndef SAILFACTOR_CORE_H
#define SAILFACTOR_CORE_H

/*
 * C API of the SailFactor Rust core (core/src/ffi). The file and accounts
 * waiting to be added stay in the core behind opaque handles; seeds never
 * leave it. Every function that returns int32_t returns SF_OK or an error
 * status; on an error its outputs are null, empty or zero. Times are
 * seconds since the Unix epoch. Text is UTF-8 and not NUL-terminated.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SF_OK 0
#define SF_INVALID_ARGUMENT 1
#define SF_NOT_KDBX 2
#define SF_UNSUPPORTED_FORMAT 4
#define SF_INVALID_CREDENTIALS 5
#define SF_INVALID_KEY_FILE 6
#define SF_CORRUPTED 7
#define SF_LIMIT_EXCEEDED 8
#define SF_NOT_FOUND 9
#define SF_WRITE_FAILED 10
#define SF_RANDOM_UNAVAILABLE 11
#define SF_NOT_OTPAUTH 12
#define SF_HOTP 13
#define SF_UNSUPPORTED_TYPE 14
#define SF_INVALID_SECRET 15
#define SF_INVALID_SETTINGS 16
#define SF_NO_CODE 17

#define SF_TEXT_ISSUER 0u
#define SF_TEXT_NAME 1u

#define SF_KIND_TOTP 0u
#define SF_KIND_HOTP 1u
#define SF_KIND_UNREADABLE 2u
#define SF_KIND_NO_CODE 3u

#define SF_ALGORITHM_SHA1 0u
#define SF_ALGORITHM_SHA256 1u
#define SF_ALGORITHM_SHA512 2u

#define SF_ENCODER_DECIMAL 0u
#define SF_ENCODER_STEAM 1u

#define SF_KDF_STANDARD 0u
#define SF_KDF_HIGH 1u
#define SF_KDF_MAXIMUM 2u

#define SF_UUID_LENGTH 16
/* The most pixels per side sf_pending_from_frame accepts. */
#define SF_MAX_FRAME_DIMENSION 4096u

typedef struct SfDatabase SfDatabase;
typedef struct SfPending SfPending;
typedef struct SfAccountList SfAccountList;

/* Text owned by the core; release it with sf_string_free, which wipes it. */
typedef struct SfString {
    uint8_t *data;
    size_t length;
} SfString;

/* A serialized file owned by the core; release it with sf_bytes_free. */
typedef struct SfBytes {
    uint8_t *data;
    size_t length;
} SfBytes;

/* The core's version; a static NUL-terminated string, never freed. */
const char *sf_core_version(void);

void sf_string_free(SfString string);
void sf_bytes_free(SfBytes bytes);

/*
 * The file. Open and create run the key derivation: call them, and save,
 * off the UI thread. Functions that take a const handle may run on several
 * threads at once, so the UI can read while a save serializes; a function
 * that takes a mutable handle, and sf_database_free, need the handle to
 * themselves. sf_database_free locks the file and wipes everything
 * decrypted.
 */
/* The format version of a KDBX file from its first twelve bytes. */
int32_t sf_kdbx_version(const uint8_t *data, size_t data_length, uint16_t *major,
                        uint16_t *minor);
int32_t sf_database_open(const uint8_t *data, size_t data_length, const uint8_t *password,
                         size_t password_length, bool has_password, const uint8_t *key_file,
                         size_t key_file_length, SfDatabase **out);
int32_t sf_database_create(const uint8_t *password, size_t password_length, const uint8_t *name,
                           size_t name_length, uint32_t level, int64_t now, SfDatabase **out,
                           SfBytes *file_out);
int32_t sf_database_save(const SfDatabase *database, SfBytes *out);
/* Whether the file was read from KDBX 3.1; it is saved as KDBX 4. */
int32_t sf_database_from_kdbx3(const SfDatabase *database, bool *from_kdbx3);
/* Argon2id at SF_KDF_* from the next save on. */
int32_t sf_database_set_kdf_level(SfDatabase *database, uint32_t level);
void sf_database_free(SfDatabase *database);

/*
 * Accounts outside the recycle bin, in document order. A kind other than
 * SF_KIND_TOTP has zero digits, period and encoder.
 */
int32_t sf_account_list(const SfDatabase *database, SfAccountList **out);
size_t sf_account_list_length(const SfAccountList *list);
int32_t sf_account_list_uuid(const SfAccountList *list, size_t index, uint8_t *uuid_out);
int32_t sf_account_list_text(const SfAccountList *list, size_t index, uint32_t column,
                             SfString *out);
int32_t sf_account_list_kind(const SfAccountList *list, size_t index, uint32_t *kind_out,
                             uint32_t *digits_out, uint32_t *period_out, uint32_t *encoder_out);
void sf_account_list_free(SfAccountList *list);

/* The code at now and the seconds until it changes. */
int32_t sf_account_code(const SfDatabase *database, const uint8_t *uuid, int64_t now,
                        SfString *code_out, uint32_t *remaining_out);
/* Adds a pending account with the issuer and name the user confirmed. */
int32_t sf_account_add(SfDatabase *database, const SfPending *pending, const uint8_t *issuer,
                       size_t issuer_length, const uint8_t *name, size_t name_length,
                       int64_t now, uint8_t *uuid_out);
int32_t sf_account_rename(SfDatabase *database, const uint8_t *uuid, const uint8_t *issuer,
                          size_t issuer_length, const uint8_t *name, size_t name_length,
                          int64_t now, bool *changed_out);
/* Whether sf_account_delete would remove the account for good. */
int32_t sf_account_deletes_permanently(const SfDatabase *database, const uint8_t *uuid,
                                       bool *permanent_out);
/* To the recycle bin, or for good when already there; permanent_out says which. */
int32_t sf_account_delete(SfDatabase *database, const uint8_t *uuid, int64_t now,
                          bool *permanent_out);

/*
 * Accounts waiting to be added. A camera frame has one byte of brightness
 * per pixel, pixel_step bytes (1 to 4) apart and row_stride bytes per row,
 * at most SF_MAX_FRAME_DIMENSION pixels per side; SF_NOT_FOUND means no QR
 * code in it. A
 * typed secret is Base32 with digits 1 to 10 and a period of 1 to 86400
 * seconds; its issuer and name are empty.
 */
int32_t sf_pending_from_frame(const uint8_t *pixels, size_t length, uint32_t width,
                              uint32_t height, uint32_t row_stride, uint32_t pixel_step,
                              SfPending **out);
int32_t sf_pending_from_uri(const uint8_t *uri, size_t uri_length, SfPending **out);
int32_t sf_pending_from_secret(const uint8_t *secret, size_t secret_length, uint32_t algorithm,
                               uint32_t digits, uint32_t period, uint32_t encoder,
                               SfPending **out);
int32_t sf_pending_text(const SfPending *pending, uint32_t column, SfString *out);
int32_t sf_pending_code(const SfPending *pending, int64_t now, SfString *code_out,
                        uint32_t *remaining_out);
void sf_pending_free(SfPending *pending);

#ifdef __cplusplus
}
#endif

#endif /* SAILFACTOR_CORE_H */
