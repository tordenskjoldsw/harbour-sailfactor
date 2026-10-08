//! Opening, creating, saving and locking an authenticator file.

use super::{
    bytes, kdbx_status, utf8, SfBytes, SfDatabase, SfMergeChanges, SF_INVALID_ARGUMENT,
    SF_KDF_HIGH, SF_KDF_MAXIMUM, SF_KDF_STANDARD, SF_OK,
};
use crate::kdbx::{self, CompositeKey, Database, KdfLevel};

fn kdf_level(level: u32) -> Option<KdfLevel> {
    match level {
        SF_KDF_STANDARD => Some(KdfLevel::Standard),
        SF_KDF_HIGH => Some(KdfLevel::High),
        SF_KDF_MAXIMUM => Some(KdfLevel::Maximum),
        _ => None,
    }
}

/// The format version of a KDBX file from its first twelve bytes, so a
/// file can be named before it is unlocked. `SF_NOT_KDBX` for anything
/// else.
///
/// # Safety
///
/// `data` must be null or valid for reads of `data_length` bytes; `major`
/// and `minor` valid for one write each.
#[no_mangle]
pub unsafe extern "C" fn sf_kdbx_version(
    data: *const u8,
    data_length: usize,
    major: *mut u16,
    minor: *mut u16,
) -> i32 {
    // SAFETY: the caller guarantees the pointers as documented.
    let (Some(major), Some(minor)) = (unsafe { major.as_mut() }, unsafe { minor.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *major = 0;
    *minor = 0;
    // SAFETY: as above.
    let Some(data) = (unsafe { bytes(data, data_length) }) else {
        return SF_INVALID_ARGUMENT;
    };
    match kdbx::version(data) {
        Ok((file_major, file_minor)) => {
            *major = file_major;
            *minor = file_minor;
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Whether the open file was read from KDBX 3.1; it is saved as KDBX 4.
///
/// # Safety
///
/// `database` must be a live handle; `from_kdbx3` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_database_from_kdbx3(
    database: *const SfDatabase,
    from_kdbx3: *mut bool,
) -> i32 {
    // SAFETY: the caller guarantees both pointers as documented.
    let Some(from_kdbx3) = (unsafe { from_kdbx3.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *from_kdbx3 = false;
    // SAFETY: as above.
    let Some(database) = (unsafe { database.as_ref() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *from_kdbx3 = database.database.from_kdbx3();
    SF_OK
}

/// Switches the file to Argon2id at `SF_KDF_*` from the next save on, as
/// for a KDBX 3.1 file that is stored as KDBX 4.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread.
#[no_mangle]
pub unsafe extern "C" fn sf_database_set_kdf_level(database: *mut SfDatabase, level: u32) -> i32 {
    // SAFETY: the caller guarantees the handle as documented.
    let (Some(database), Some(level)) = (unsafe { database.as_mut() }, kdf_level(level)) else {
        return SF_INVALID_ARGUMENT;
    };
    database.database.set_kdf_level(level);
    SF_OK
}

/// Opens a KDBX 4 file, or a KDBX 3.1 file as KDBX 4. At least one of
/// password and key file must be given. Runs the KDF: call it off the UI
/// thread.
///
/// # Safety
///
/// Each pointer must be null or valid for reads of its length; `out` must
/// be valid for one write. On success `*out` receives a handle to release
/// with `sf_database_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_database_open(
    data: *const u8,
    data_length: usize,
    password: *const u8,
    password_length: usize,
    has_password: bool,
    key_file: *const u8,
    key_file_length: usize,
    out: *mut *mut SfDatabase,
) -> i32 {
    // SAFETY: the caller guarantees the pointers as documented.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    // SAFETY: as above.
    let (Some(data), Some(password), Some(key_file)) = (
        unsafe { bytes(data, data_length) },
        unsafe { bytes(password, password_length) },
        unsafe { bytes(key_file, key_file_length) },
    ) else {
        return SF_INVALID_ARGUMENT;
    };
    let opened = CompositeKey::new(
        has_password.then_some(password),
        (!key_file.is_empty()).then_some(key_file),
    )
    .and_then(|key| Database::open(data, key));
    match opened {
        Ok(database) => {
            *out = Box::into_raw(Box::new(SfDatabase { database }));
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Creates an empty file named `name`, protected by `password` with the
/// key derivation `SF_KDF_*`, and returns it serialized for writing along
/// with the unlocked handle. Runs the KDF: call it off the UI thread.
///
/// # Safety
///
/// `password` and `name` must be valid for reads of their lengths, `name`
/// UTF-8; `out` and `file_out` valid for one write each. Release the
/// results with `sf_database_free` and `sf_bytes_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_database_create(
    password: *const u8,
    password_length: usize,
    name: *const u8,
    name_length: usize,
    level: u32,
    now: i64,
    out: *mut *mut SfDatabase,
    file_out: *mut SfBytes,
) -> i32 {
    // SAFETY: the caller guarantees both pointers are valid for a write.
    let (Some(out), Some(file_out)) = (unsafe { out.as_mut() }, unsafe { file_out.as_mut() })
    else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    *file_out = SfBytes::EMPTY;
    // SAFETY: the caller guarantees the inputs as documented.
    let (Some(password), Some(name), Some(level)) = (
        unsafe { bytes(password, password_length) }.filter(|password| !password.is_empty()),
        unsafe { utf8(name, name_length) },
        kdf_level(level),
    ) else {
        return SF_INVALID_ARGUMENT;
    };
    let created = CompositeKey::new(Some(password), None)
        .and_then(|key| Database::create(key, name, level, now))
        .and_then(|database| Ok((database.save()?, database)));
    match created {
        Ok((file, database)) => {
            *file_out = SfBytes::new(file);
            *out = Box::into_raw(Box::new(SfDatabase { database }));
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Serializes the file with fresh seeds, verified by decrypting it again.
/// Runs the KDF: call it off the UI thread.
///
/// # Safety
///
/// `database` must be a live handle that no other thread modifies or frees
/// meanwhile; `out` must be valid for one write. Release the result with
/// `sf_bytes_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_database_save(database: *const SfDatabase, out: *mut SfBytes) -> i32 {
    // SAFETY: the caller guarantees both pointers as documented.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = SfBytes::EMPTY;
    // SAFETY: as above.
    let Some(database) = (unsafe { database.as_ref() }) else {
        return SF_INVALID_ARGUMENT;
    };
    match database.database.save() {
        Ok(file) => {
            *out = SfBytes::new(file);
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Opens another copy of the file, such as a download from Nextcloud or the
/// file from the computer, with the credentials `like` was unlocked with;
/// they never leave the core. Runs the KDF: call it off the UI thread.
///
/// # Safety
///
/// `like` must be a live handle that no thread modifies meanwhile; `data`
/// null or valid for reads of `data_length` bytes; `out` valid for one
/// write. Release the result with `sf_database_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_database_open_like(
    like: *const SfDatabase,
    data: *const u8,
    data_length: usize,
    out: *mut *mut SfDatabase,
) -> i32 {
    // SAFETY: the caller guarantees the pointers as documented.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    // SAFETY: as above.
    let (Some(like), Some(data)) = (unsafe { like.as_ref() }, unsafe {
        bytes(data, data_length)
    }) else {
        return SF_INVALID_ARGUMENT;
    };
    match like.database.open_like(data) {
        Ok(database) => {
            *out = Box::into_raw(Box::new(SfDatabase { database }));
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Merges another copy of the file into `database` as KeePassXC does, and
/// applies deletions recorded in either copy unless the item changed later.
/// Nothing changes on an error.
///
/// # Safety
///
/// `database` must be a live handle no other thread uses; `source` a live
/// handle; `out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sf_database_merge(
    database: *mut SfDatabase,
    source: *const SfDatabase,
    out: *mut SfMergeChanges,
) -> i32 {
    // SAFETY: the caller guarantees the pointers as documented.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = SfMergeChanges::default();
    if std::ptr::eq(database, source) {
        return SF_INVALID_ARGUMENT;
    }
    // SAFETY: as above; the two handles differ.
    let (Some(database), Some(source)) = (unsafe { database.as_mut() }, unsafe { source.as_ref() })
    else {
        return SF_INVALID_ARGUMENT;
    };
    match database.database.merge_from(&source.database) {
        Ok(changes) => {
            *out = SfMergeChanges {
                added: changes.added,
                modified: changes.modified,
                moved: changes.moved,
                deleted: changes.deleted,
                metadata: changes.metadata,
            };
            SF_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Locks the file: drops and wipes everything decrypted.
///
/// # Safety
///
/// `database` must be null or a handle from this API that has not been
/// freed.
#[no_mangle]
pub unsafe extern "C" fn sf_database_free(database: *mut SfDatabase) {
    if !database.is_null() {
        // SAFETY: the handle came from Box::into_raw in this module.
        drop(unsafe { Box::from_raw(database) });
    }
}
