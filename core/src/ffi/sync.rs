//! Nextcloud sync settings, kept in an entry of the file so the app
//! password has the master password in front of it.

use zeroize::Zeroizing;

use super::{
    kdbx_status, utf8, write_uuid, SfDatabase, SfString, SF_INVALID_ARGUMENT, SF_NOT_FOUND, SF_OK,
    SF_SYNC_APP_PASSWORD, SF_SYNC_CERTIFICATE, SF_SYNC_PATH, SF_SYNC_SERVER, SF_SYNC_USER,
};
use crate::accounts::UUID_LENGTH;
use crate::kdbx::SyncSettings;

/// One `SF_SYNC_*` setting from the file's sync entry, or `SF_NOT_FOUND`
/// without one. Release the result with `sf_string_free`.
///
/// # Safety
///
/// `database` must be a live handle; `out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_database_sync_setting(
    database: *const SfDatabase,
    setting: u32,
    out: *mut SfString,
) -> i32 {
    // SAFETY: the caller guarantees the pointers as documented.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = SfString::EMPTY;
    // SAFETY: as above.
    let Some(database) = (unsafe { database.as_ref() }) else {
        return SF_INVALID_ARGUMENT;
    };
    let Some(settings) = database.database.sync_settings() else {
        return SF_NOT_FOUND;
    };
    let value = match setting {
        SF_SYNC_SERVER => &settings.server,
        SF_SYNC_USER => &settings.user,
        SF_SYNC_APP_PASSWORD => &settings.app_password,
        SF_SYNC_PATH => &settings.path,
        SF_SYNC_CERTIFICATE => &settings.certificate,
        _ => return SF_INVALID_ARGUMENT,
    };
    *out = SfString::new(value);
    SF_OK
}

/// Stores the sync settings, UTF-8 each, in the file's sync entry, created
/// in the root group when there is none, and writes its UUID to `uuid_out`.
/// The change is in memory until the next save.
///
/// # Safety
///
/// Each string pointer must be null or valid for reads of its length;
/// `database` a live handle no other thread uses; `uuid_out` valid for
/// writes of 16 bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sf_database_set_sync_settings(
    database: *mut SfDatabase,
    server: *const u8,
    server_length: usize,
    user: *const u8,
    user_length: usize,
    app_password: *const u8,
    app_password_length: usize,
    path: *const u8,
    path_length: usize,
    certificate: *const u8,
    certificate_length: usize,
    now: i64,
    uuid_out: *mut u8,
) -> i32 {
    if uuid_out.is_null() {
        return SF_INVALID_ARGUMENT;
    }
    // SAFETY: uuid_out is valid for 16 bytes, as the caller guarantees.
    unsafe { write_uuid(uuid_out, &[0; UUID_LENGTH]) };
    // SAFETY: the caller guarantees the pointers as documented.
    let text =
        |data, length| unsafe { utf8(data, length) }.map(|text| Zeroizing::new(text.to_owned()));
    // SAFETY: as above.
    let (
        Some(database),
        Some(server),
        Some(user),
        Some(app_password),
        Some(path),
        Some(certificate),
    ) = (
        unsafe { database.as_mut() },
        text(server, server_length),
        text(user, user_length),
        text(app_password, app_password_length),
        text(path, path_length),
        text(certificate, certificate_length),
    )
    else {
        return SF_INVALID_ARGUMENT;
    };
    let settings = SyncSettings {
        server,
        user,
        app_password,
        path,
        certificate,
    };
    match database.database.set_sync_settings(&settings, now) {
        Ok(uuid) => {
            // SAFETY: as above.
            unsafe { write_uuid(uuid_out, &uuid) };
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}
