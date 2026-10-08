//! Listing accounts, their codes, and adding, renaming and deleting them.

use super::{
    account_status, kdbx_status, read_uuid, unix_seconds, utf8, write_uuid, SfAccountList,
    SfDatabase, SfPending, SfString, SF_ENCODER_DECIMAL, SF_ENCODER_STEAM, SF_INVALID_ARGUMENT,
    SF_KIND_HOTP, SF_KIND_NO_CODE, SF_KIND_TOTP, SF_KIND_UNREADABLE, SF_NOT_FOUND, SF_OK,
    SF_TEXT_ISSUER, SF_TEXT_NAME,
};
use crate::accounts::{self, Account, AccountKind, UUID_LENGTH};
use crate::otp::Encoder;

/// Lists the accounts outside the recycle bin in document order.
///
/// # Safety
///
/// `database` must be a live handle; `out` valid for one write. Release the
/// list with `sf_account_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list(
    database: *const SfDatabase,
    out: *mut *mut SfAccountList,
) -> i32 {
    // SAFETY: the caller guarantees both pointers as documented.
    let (Some(database), Some(out)) = (unsafe { database.as_ref() }, unsafe { out.as_mut() })
    else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    match accounts::list(&database.database) {
        Ok(accounts) => {
            *out = Box::into_raw(Box::new(SfAccountList { accounts }));
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// # Safety
///
/// `list` must be a live list.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list_length(list: *const SfAccountList) -> usize {
    // SAFETY: guaranteed by the caller.
    unsafe { list.as_ref() }.map_or(0, |list| list.accounts.len())
}

/// # Safety
///
/// `list` must be a live list; `uuid_out` valid for writes of 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list_uuid(
    list: *const SfAccountList,
    index: usize,
    uuid_out: *mut u8,
) -> i32 {
    if uuid_out.is_null() {
        return SF_INVALID_ARGUMENT;
    }
    // SAFETY: uuid_out is valid for 16 bytes, as the caller guarantees.
    unsafe { write_uuid(uuid_out, &[0; UUID_LENGTH]) };
    // SAFETY: guaranteed by the caller.
    let Some(account) = (unsafe { account(list, index) }) else {
        return SF_NOT_FOUND;
    };
    // SAFETY: as above.
    unsafe { write_uuid(uuid_out, &account.uuid) };
    SF_OK
}

/// The issuer (`SF_TEXT_ISSUER`) or account name (`SF_TEXT_NAME`).
///
/// # Safety
///
/// `list` must be a live list; `out` valid for one write. Release the text
/// with `sf_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list_text(
    list: *const SfAccountList,
    index: usize,
    column: u32,
    out: *mut SfString,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = SfString::EMPTY;
    // SAFETY: guaranteed by the caller.
    let Some(account) = (unsafe { account(list, index) }) else {
        return SF_NOT_FOUND;
    };
    *out = match column {
        SF_TEXT_ISSUER => SfString::new(&account.issuer),
        SF_TEXT_NAME => SfString::new(&account.name),
        _ => return SF_INVALID_ARGUMENT,
    };
    SF_OK
}

/// What an account can show (`SF_KIND_*`); for `SF_KIND_TOTP` also its
/// digits, period in seconds and `SF_ENCODER_*`, zero otherwise.
///
/// # Safety
///
/// `list` must be a live list; each output valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list_kind(
    list: *const SfAccountList,
    index: usize,
    kind_out: *mut u32,
    digits_out: *mut u32,
    period_out: *mut u32,
    encoder_out: *mut u32,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(kind_out), Some(digits_out), Some(period_out), Some(encoder_out)) = (unsafe {
        (
            kind_out.as_mut(),
            digits_out.as_mut(),
            period_out.as_mut(),
            encoder_out.as_mut(),
        )
    }) else {
        return SF_INVALID_ARGUMENT;
    };
    *kind_out = 0;
    *digits_out = 0;
    *period_out = 0;
    *encoder_out = 0;
    // SAFETY: guaranteed by the caller.
    let Some(account) = (unsafe { account(list, index) }) else {
        return SF_NOT_FOUND;
    };
    let (kind, digits, period, encoder) = match account.kind {
        AccountKind::Totp {
            digits,
            period,
            encoder,
        } => (
            SF_KIND_TOTP,
            u32::from(digits),
            period,
            match encoder {
                Encoder::Decimal => SF_ENCODER_DECIMAL,
                Encoder::Steam => SF_ENCODER_STEAM,
            },
        ),
        AccountKind::Hotp => (SF_KIND_HOTP, 0, 0, 0),
        AccountKind::Unreadable => (SF_KIND_UNREADABLE, 0, 0, 0),
        AccountKind::NoCode => (SF_KIND_NO_CODE, 0, 0, 0),
    };
    *kind_out = kind;
    *digits_out = digits;
    *period_out = period;
    *encoder_out = encoder;
    SF_OK
}

/// Whether the account's entry stores a password, such as one from
/// KeePassXC. The password itself never leaves the core.
///
/// # Safety
///
/// `list` must be a live list; `has_password_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list_has_password(
    list: *const SfAccountList,
    index: usize,
    has_password_out: *mut bool,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(has_password_out) = (unsafe { has_password_out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *has_password_out = false;
    // SAFETY: guaranteed by the caller.
    let Some(account) = (unsafe { account(list, index) }) else {
        return SF_NOT_FOUND;
    };
    *has_password_out = account.has_password;
    SF_OK
}

/// Releases a list and wipes its names.
///
/// # Safety
///
/// `list` must be null or a list from this API that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sf_account_list_free(list: *mut SfAccountList) {
    if !list.is_null() {
        // SAFETY: the list came from Box::into_raw in this module.
        drop(unsafe { Box::from_raw(list) });
    }
}

/// The code of an account at `now` (seconds since the Unix epoch) and the
/// seconds until it changes.
///
/// # Safety
///
/// `database` must be a live handle; `uuid` valid for 16 bytes; `code_out`
/// and `remaining_out` valid for one write each. Release the code with
/// `sf_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_account_code(
    database: *const SfDatabase,
    uuid: *const u8,
    now: i64,
    code_out: *mut SfString,
    remaining_out: *mut u32,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(code_out), Some(remaining_out)) =
        (unsafe { (code_out.as_mut(), remaining_out.as_mut()) })
    else {
        return SF_INVALID_ARGUMENT;
    };
    *code_out = SfString::EMPTY;
    *remaining_out = 0;
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(uuid), Some(now)) =
        (unsafe { (database.as_ref(), read_uuid(uuid), unix_seconds(now)) })
    else {
        return SF_INVALID_ARGUMENT;
    };
    match accounts::code(&database.database, &uuid, now) {
        Ok((code, remaining)) => {
            *code_out = SfString::new(&code);
            *remaining_out = remaining;
            SF_OK
        }
        Err(error) => account_status(error),
    }
}

/// Adds the pending account with the issuer and name the user confirmed,
/// and writes its UUID. The pending handle stays valid.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `pending` a live handle; `issuer` and `name` UTF-8 of their lengths;
/// `uuid_out` valid for writes of 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn sf_account_add(
    database: *mut SfDatabase,
    pending: *const SfPending,
    issuer: *const u8,
    issuer_length: usize,
    name: *const u8,
    name_length: usize,
    now: i64,
    uuid_out: *mut u8,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(pending), Some(issuer), Some(name)) = (unsafe {
        (
            database.as_mut(),
            pending.as_ref(),
            utf8(issuer, issuer_length),
            utf8(name, name_length),
        )
    }) else {
        return SF_INVALID_ARGUMENT;
    };
    if uuid_out.is_null() {
        return SF_INVALID_ARGUMENT;
    }
    // SAFETY: uuid_out is valid for 16 bytes, as the caller guarantees.
    unsafe { write_uuid(uuid_out, &[0; UUID_LENGTH]) };
    match accounts::add(&mut database.database, issuer, name, &pending.settings, now) {
        Ok(uuid) => {
            // SAFETY: uuid_out is valid for 16 bytes, as the caller guarantees.
            unsafe { write_uuid(uuid_out, &uuid) };
            SF_OK
        }
        Err(error) => account_status(error),
    }
}

/// Renames an account; `changed_out` tells whether anything changed.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread; `uuid`
/// valid for 16 bytes; `issuer` and `name` UTF-8 of their lengths;
/// `changed_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_account_rename(
    database: *mut SfDatabase,
    uuid: *const u8,
    issuer: *const u8,
    issuer_length: usize,
    name: *const u8,
    name_length: usize,
    now: i64,
    changed_out: *mut bool,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(changed_out) = (unsafe { changed_out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *changed_out = false;
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(uuid), Some(issuer), Some(name)) = (unsafe {
        (
            database.as_mut(),
            read_uuid(uuid),
            utf8(issuer, issuer_length),
            utf8(name, name_length),
        )
    }) else {
        return SF_INVALID_ARGUMENT;
    };
    match accounts::rename(&mut database.database, &uuid, issuer, name, now) {
        Ok(changed) => {
            *changed_out = changed;
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Whether `sf_account_delete` would remove the account for good, so the
/// confirmation can say so.
///
/// # Safety
///
/// `database` must be a live handle; `uuid` valid for 16 bytes;
/// `permanent_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_account_deletes_permanently(
    database: *const SfDatabase,
    uuid: *const u8,
    permanent_out: *mut bool,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(permanent_out) = (unsafe { permanent_out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *permanent_out = false;
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(uuid)) = (unsafe { (database.as_ref(), read_uuid(uuid)) }) else {
        return SF_INVALID_ARGUMENT;
    };
    match accounts::deletes_permanently(&database.database, &uuid) {
        Ok(permanent) => {
            *permanent_out = permanent;
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Moves an account to the recycle bin, or removes it for good when it is
/// already there or the bin is off; `permanent_out` tells which.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread; `uuid`
/// valid for 16 bytes; `permanent_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_account_delete(
    database: *mut SfDatabase,
    uuid: *const u8,
    now: i64,
    permanent_out: *mut bool,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(permanent_out) = (unsafe { permanent_out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *permanent_out = false;
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(uuid)) = (unsafe { (database.as_mut(), read_uuid(uuid)) }) else {
        return SF_INVALID_ARGUMENT;
    };
    match accounts::delete(&mut database.database, &uuid, now) {
        Ok(permanent) => {
            *permanent_out = permanent;
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// The number of entries and groups in the recycle bin, at any depth.
///
/// # Safety
///
/// `database` must be a live handle; `items_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_database_recycle_bin_items(
    database: *const SfDatabase,
    items_out: *mut usize,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(items_out) = (unsafe { items_out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *items_out = 0;
    // SAFETY: guaranteed by the caller.
    let Some(database) = (unsafe { database.as_ref() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *items_out = accounts::recycle_bin_items(&database.database);
    SF_OK
}

/// Removes everything in the recycle bin for good, as KeePassXC does, and
/// records it as deleted; `changed_out` tells whether anything was removed.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `changed_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_database_empty_recycle_bin(
    database: *mut SfDatabase,
    now: i64,
    changed_out: *mut bool,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(changed_out) = (unsafe { changed_out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *changed_out = false;
    // SAFETY: guaranteed by the caller.
    let Some(database) = (unsafe { database.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    match accounts::empty_recycle_bin(&mut database.database, now) {
        Ok(changed) => {
            *changed_out = changed;
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// # Safety
///
/// `list` must be null or a live list.
unsafe fn account<'a>(list: *const SfAccountList, index: usize) -> Option<&'a Account> {
    // SAFETY: guaranteed by the caller.
    unsafe { list.as_ref() }.and_then(|list| list.accounts.get(index))
}
