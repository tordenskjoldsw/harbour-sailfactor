//! Nextcloud sync settings, kept in an entry of the file so the app
//! password has the master password in front of it.

use zeroize::Zeroizing;

use super::{
    kdbx_status, utf8, write_uuid, StDatabase, StString, ST_INVALID_ARGUMENT, ST_NOT_FOUND, ST_OK,
    ST_SYNC_APP_PASSWORD, ST_SYNC_CERTIFICATE, ST_SYNC_PATH, ST_SYNC_SERVER, ST_SYNC_USER,
};
use crate::accounts::UUID_LENGTH;
use crate::kdbx::SyncSettings;

/// One `ST_SYNC_*` setting from the file's sync entry, or `ST_NOT_FOUND`
/// without one. Release the result with `st_string_free`.
///
/// # Safety
///
/// `database` must be a live handle; `out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn st_database_sync_setting(
    database: *const StDatabase,
    setting: u32,
    out: *mut StString,
) -> i32 {
    // SAFETY: the caller guarantees the pointers as documented.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = StString::EMPTY;
    // SAFETY: as above.
    let Some(database) = (unsafe { database.as_ref() }) else {
        return ST_INVALID_ARGUMENT;
    };
    let Some(settings) = database.database.sync_settings() else {
        return ST_NOT_FOUND;
    };
    let value = match setting {
        ST_SYNC_SERVER => &settings.server,
        ST_SYNC_USER => &settings.user,
        ST_SYNC_APP_PASSWORD => &settings.app_password,
        ST_SYNC_PATH => &settings.path,
        ST_SYNC_CERTIFICATE => &settings.certificate,
        _ => return ST_INVALID_ARGUMENT,
    };
    *out = StString::new(value);
    ST_OK
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
pub unsafe extern "C" fn st_database_set_sync_settings(
    database: *mut StDatabase,
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
        return ST_INVALID_ARGUMENT;
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
        return ST_INVALID_ARGUMENT;
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
            ST_OK
        }
        Err(error) => kdbx_status(error),
    }
}
