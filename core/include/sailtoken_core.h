#ifndef SAILTOKEN_CORE_H
#define SAILTOKEN_CORE_H

/*
 * C API of the SailToken Rust core (core/src/ffi). The file and accounts
 * waiting to be added stay in the core behind opaque handles; seeds never
 * leave it. Every function that returns int32_t returns ST_OK or an error
 * status; on an error its outputs are null, empty or zero. Times are
 * seconds since the Unix epoch. Text is UTF-8 and not NUL-terminated.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ST_OK 0
#define ST_INVALID_ARGUMENT 1
#define ST_NOT_KDBX 2
#define ST_UNSUPPORTED_FORMAT 4
#define ST_INVALID_CREDENTIALS 5
#define ST_INVALID_KEY_FILE 6
#define ST_CORRUPTED 7
#define ST_LIMIT_EXCEEDED 8
#define ST_NOT_FOUND 9
#define ST_WRITE_FAILED 10
#define ST_RANDOM_UNAVAILABLE 11
#define ST_NOT_OTPAUTH 12
#define ST_HOTP 13
#define ST_UNSUPPORTED_TYPE 14
#define ST_INVALID_SECRET 15
#define ST_INVALID_SETTINGS 16
#define ST_NO_CODE 17
#define ST_ALREADY_SCANNED 18
#define ST_NOT_EXPORT 19
#define ST_OTHER_EXPORT 20
#define ST_EXPORT_CODE 21
#define ST_PASSWORD_REQUIRED 22

#define ST_TEXT_ISSUER 0u
#define ST_TEXT_NAME 1u

#define ST_KIND_TOTP 0u
#define ST_KIND_HOTP 1u
#define ST_KIND_UNREADABLE 2u
#define ST_KIND_NO_CODE 3u

#define ST_ALGORITHM_SHA1 0u
#define ST_ALGORITHM_SHA256 1u
#define ST_ALGORITHM_SHA512 2u

#define ST_ENCODER_DECIMAL 0u
#define ST_ENCODER_STEAM 1u

/* Nextcloud sync settings, kept in an entry of the file. */
#define ST_SYNC_SERVER 0u
#define ST_SYNC_USER 1u
#define ST_SYNC_APP_PASSWORD 2u
#define ST_SYNC_PATH 3u
/* SHA-256 fingerprint of a pinned self-signed certificate, or empty. */
#define ST_SYNC_CERTIFICATE 4u

#define ST_KDF_STANDARD 0u
#define ST_KDF_HIGH 1u
#define ST_KDF_MAXIMUM 2u

#define ST_UUID_LENGTH 16
/* The most pixels per side st_pending_from_frame accepts. */
#define ST_MAX_FRAME_DIMENSION 4096u

typedef struct StDatabase StDatabase;
typedef struct StPending StPending;
typedef struct StAccountList StAccountList;
typedef struct StImport StImport;

/* Text owned by the core; release it with st_string_free, which wipes it. */
typedef struct StString {
    uint8_t *data;
    size_t length;
} StString;

/* A serialized file owned by the core; release it with st_bytes_free. */
typedef struct StBytes {
    uint8_t *data;
    size_t length;
} StBytes;

/* What st_database_merge changed. */
/* What a complete import holds: accounts to offer, and entries skipped
 * because they are counter-based, of a kind SailToken does not compute, or
 * unreadable. */
typedef struct StImportCounts {
    size_t accounts;
    size_t hotp;
    size_t unsupported;
    size_t invalid;
} StImportCounts;

typedef struct StMergeChanges {
    size_t added;
    size_t modified;
    size_t moved;
    size_t deleted;
    bool metadata;
} StMergeChanges;

/* The core's version; a static NUL-terminated string, never freed. */
const char *st_core_version(void);

void st_string_free(StString string);
void st_bytes_free(StBytes bytes);

/*
 * The file. Open and create run the key derivation: call them, and save,
 * off the UI thread. Functions that take a const handle may run on several
 * threads at once, so the UI can read while a save serializes; a function
 * that takes a mutable handle, and st_database_free, need the handle to
 * themselves. st_database_free locks the file and wipes everything
 * decrypted.
 */
/* The format version of a KDBX file from its first twelve bytes. */
int32_t st_kdbx_version(const uint8_t *data, size_t data_length, uint16_t *major,
                        uint16_t *minor);
int32_t st_database_open(const uint8_t *data, size_t data_length, const uint8_t *password,
                         size_t password_length, bool has_password, const uint8_t *key_file,
                         size_t key_file_length, StDatabase **out);
int32_t st_database_create(const uint8_t *password, size_t password_length, const uint8_t *name,
                           size_t name_length, uint32_t level, int64_t now, StDatabase **out,
                           StBytes *file_out);
int32_t st_database_save(const StDatabase *database, StBytes *out);
/* Whether the file was read from KDBX 3.1; it is saved as KDBX 4. */
int32_t st_database_from_kdbx3(const StDatabase *database, bool *from_kdbx3);
/* Argon2id at ST_KDF_* from the next save on. */
int32_t st_database_set_kdf_level(StDatabase *database, uint32_t level);
/* Opens another copy of the file with the credentials like was unlocked
 * with; they never leave the core. Runs the KDF; call off the UI thread
 * while nothing modifies like. */
int32_t st_database_open_like(const StDatabase *like, const uint8_t *data, size_t data_length,
                              StDatabase **out);
/* Merges another copy into database as KeePassXC does, and applies
 * deletions recorded in either copy unless the item changed later.
 * Nothing changes on an error. */
int32_t st_database_merge(StDatabase *database, const StDatabase *source, StMergeChanges *out);
/* One ST_SYNC_* setting; ST_NOT_FOUND when the file has no sync entry. */
int32_t st_database_sync_setting(const StDatabase *database, uint32_t setting, StString *out);
/* Stores the settings (UTF-8 each) in the sync entry, created in the root
 * group when missing; uuid_out receives its 16-byte UUID. In memory until
 * the next st_database_save. The sync entry is not listed as an account. */
int32_t st_database_set_sync_settings(StDatabase *database, const uint8_t *server,
                                      size_t server_length, const uint8_t *user,
                                      size_t user_length, const uint8_t *app_password,
                                      size_t app_password_length, const uint8_t *path,
                                      size_t path_length, const uint8_t *certificate,
                                      size_t certificate_length, int64_t now,
                                      uint8_t *uuid_out);
void st_database_free(StDatabase *database);

/*
 * Accounts outside the recycle bin, in document order. A kind other than
 * ST_KIND_TOTP has zero digits, period and encoder.
 */
int32_t st_account_list(const StDatabase *database, StAccountList **out);
size_t st_account_list_length(const StAccountList *list);
int32_t st_account_list_uuid(const StAccountList *list, size_t index, uint8_t *uuid_out);
int32_t st_account_list_text(const StAccountList *list, size_t index, uint32_t column,
                             StString *out);
int32_t st_account_list_kind(const StAccountList *list, size_t index, uint32_t *kind_out,
                             uint32_t *digits_out, uint32_t *period_out, uint32_t *encoder_out);
/* Whether the account's entry stores a password; the password never
 * leaves the core. */
int32_t st_account_list_has_password(const StAccountList *list, size_t index,
                                     bool *has_password_out);
void st_account_list_free(StAccountList *list);

/* The code at now and the seconds until it changes. */
int32_t st_account_code(const StDatabase *database, const uint8_t *uuid, int64_t now,
                        StString *code_out, uint32_t *remaining_out);
/* Adds a pending account with the issuer and name the user confirmed. */
int32_t st_account_add(StDatabase *database, const StPending *pending, const uint8_t *issuer,
                       size_t issuer_length, const uint8_t *name, size_t name_length,
                       int64_t now, uint8_t *uuid_out);
int32_t st_account_rename(StDatabase *database, const uint8_t *uuid, const uint8_t *issuer,
                          size_t issuer_length, const uint8_t *name, size_t name_length,
                          int64_t now, bool *changed_out);
/* Moves the account in front of before, or to the end when before is
 * null; the order is SailToken's own, stored in the file. */
int32_t st_account_move(StDatabase *database, const uint8_t *uuid, const uint8_t *before,
                        bool *changed_out);
/* Whether st_account_delete would remove the account for good. */
int32_t st_account_deletes_permanently(const StDatabase *database, const uint8_t *uuid,
                                       bool *permanent_out);
/* To the recycle bin, or for good when already there; permanent_out says which. */
int32_t st_account_delete(StDatabase *database, const uint8_t *uuid, int64_t now,
                          bool *permanent_out);
/* Entries and groups in the recycle bin, at any depth. */
int32_t st_database_recycle_bin_items(const StDatabase *database, size_t *items_out);
/* Removes everything in the recycle bin for good and records it as deleted,
 * so merges and the sync remove it elsewhere too. */
int32_t st_database_empty_recycle_bin(StDatabase *database, int64_t now, bool *changed_out);

/*
 * Accounts waiting to be added. A camera frame has one byte of brightness
 * per pixel, pixel_step bytes (1 to 4) apart and row_stride bytes per row,
 * at most ST_MAX_FRAME_DIMENSION pixels per side; ST_NOT_FOUND means no QR
 * code in it, ST_EXPORT_CODE an export code of another app, which the
 * import reads. A typed secret is Base32 with digits 1 to 10 and a period
 * of 1 to 86400 seconds; its issuer and name are empty.
 */
int32_t st_pending_from_frame(const uint8_t *pixels, size_t length, uint32_t width,
                              uint32_t height, uint32_t row_stride, uint32_t pixel_step,
                              StPending **out);
int32_t st_pending_from_uri(const uint8_t *uri, size_t uri_length, StPending **out);
int32_t st_pending_from_secret(const uint8_t *secret, size_t secret_length, uint32_t algorithm,
                               uint32_t digits, uint32_t period, uint32_t encoder,
                               StPending **out);
int32_t st_pending_text(const StPending *pending, uint32_t column, StString *out);
int32_t st_pending_code(const StPending *pending, int64_t now, StString *code_out,
                        uint32_t *remaining_out);
void st_pending_free(StPending *pending);

/*
 * Import from another app: its export codes (Google Authenticator's
 * otpauth-migration format) are scanned one by one, in any order. A frame
 * is read as for st_pending_from_frame. ST_OK: a new code;
 * ST_ALREADY_SCANNED: a code scanned before; ST_NOT_EXPORT: a QR code that
 * is no export code; ST_OTHER_EXPORT: a code of another export;
 * ST_UNSUPPORTED_FORMAT: an export code SailToken cannot read; ST_CORRUPTED:
 * a QR code that could not be decoded. scanned_out and size_out count the
 * codes scanned and the codes of the export (0 before the first); the
 * import is complete when they are equal. The other functions need a
 * complete import. st_import_duplicates writes 1 per account whose secret
 * the file already has; st_import_add adds the accounts whose selected
 * byte is not 0 and reports how many it added, also on an error.
 */
StImport *st_import_new(void);
int32_t st_import_from_frame(StImport *import, const uint8_t *pixels, size_t length,
                             uint32_t width, uint32_t height, uint32_t row_stride,
                             uint32_t pixel_step, uint32_t *scanned_out, uint32_t *size_out);
int32_t st_import_counts(const StImport *import, StImportCounts *out);
int32_t st_import_text(const StImport *import, size_t index, uint32_t column, StString *out);
int32_t st_import_duplicates(const StDatabase *database, const StImport *import,
                             uint8_t *flags_out, size_t count);
int32_t st_import_add(StDatabase *database, const StImport *import, const uint8_t *selected,
                      size_t count, int64_t now, size_t *added_out);
void st_import_free(StImport *import);

#ifdef __cplusplus
}
#endif

#endif /* SAILTOKEN_CORE_H */
