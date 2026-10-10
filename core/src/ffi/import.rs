//! Moving accounts from another app: its export codes are scanned one by
//! one into an `StImport`, which then offers the accounts they hold. The
//! codes and secrets never leave the core; the bridge gets progress,
//! issuers, names and which accounts the file already has.

use std::slice;

use super::{
    bytes, decode_frame, import_status, kdbx_status, qr_status, StDatabase, StImport,
    StImportCounts, StString, ST_ALREADY_SCANNED, ST_INVALID_ARGUMENT, ST_OK, ST_TEXT_ISSUER,
    ST_TEXT_NAME,
};
use crate::accounts;
use crate::import::{read_aegis, read_migration_uri, Import, MigrationBatch, SkipReason};

pub(super) enum ImportState {
    Empty,
    Collecting(MigrationBatch),
    /// All codes are in; `size` is how many there were.
    Done {
        import: Import,
        size: usize,
    },
}

impl StImport {
    fn add(&mut self, uri: &str) -> i32 {
        let code = match read_migration_uri(uri) {
            Ok(code) => code,
            Err(error) => return import_status(error),
        };
        let (state, status) = match std::mem::replace(&mut self.state, ImportState::Empty) {
            ImportState::Empty => (ImportState::Collecting(MigrationBatch::new(code)), ST_OK),
            ImportState::Collecting(mut batch) => {
                let status = match batch.add(code) {
                    Ok(true) => ST_OK,
                    Ok(false) => ST_ALREADY_SCANNED,
                    Err(error) => import_status(error),
                };
                (ImportState::Collecting(batch), status)
            }
            done @ ImportState::Done { .. } => (done, ST_ALREADY_SCANNED),
        };
        self.state = match state {
            ImportState::Collecting(batch) if batch.is_complete() => {
                let size = batch.size();
                match batch.finish() {
                    Ok(import) => ImportState::Done { import, size },
                    Err(batch) => ImportState::Collecting(batch),
                }
            }
            state => state,
        };
        status
    }

    fn progress(&self) -> (usize, usize) {
        match &self.state {
            ImportState::Empty => (0, 0),
            ImportState::Collecting(batch) => (batch.scanned(), batch.size()),
            ImportState::Done { size, .. } => (*size, *size),
        }
    }

    fn import(&self) -> Option<&Import> {
        match &self.state {
            ImportState::Done { import, .. } => Some(import),
            _ => None,
        }
    }
}

/// An empty import, ready for the first export code. Release it with
/// `st_import_free`.
#[no_mangle]
pub extern "C" fn st_import_new() -> *mut StImport {
    Box::into_raw(Box::new(StImport {
        state: ImportState::Empty,
    }))
}

/// Decodes the first QR code in a camera frame, as `st_pending_from_frame`
/// does, and adds it to the export being collected. `ST_OK`: a new code;
/// `ST_ALREADY_SCANNED`: a code scanned before; `ST_NOT_EXPORT`: a QR code
/// that is no export code; `ST_OTHER_EXPORT`: a code of another export;
/// `ST_UNSUPPORTED_FORMAT`: an export code SailToken cannot read;
/// `ST_CORRUPTED`: a QR code that could not be decoded; `ST_NOT_FOUND`: no
/// code in the frame. `scanned_out` and `size_out` get the codes scanned and
/// the codes of the export, both 0 before the first; the import is
/// complete when they are equal.
///
/// # Safety
///
/// `import` must be a live handle not in use by another thread; `pixels`
/// valid for reads of `length` bytes; `scanned_out` and `size_out` valid
/// for one write each.
#[no_mangle]
pub unsafe extern "C" fn st_import_from_frame(
    import: *mut StImport,
    pixels: *const u8,
    length: usize,
    width: u32,
    height: u32,
    row_stride: u32,
    pixel_step: u32,
    scanned_out: *mut u32,
    size_out: *mut u32,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(import), Some(scanned_out), Some(size_out), Some(pixels)) = (unsafe {
        (
            import.as_mut(),
            scanned_out.as_mut(),
            size_out.as_mut(),
            bytes(pixels, length),
        )
    }) else {
        return ST_INVALID_ARGUMENT;
    };
    let status = if pixels.is_empty() {
        ST_INVALID_ARGUMENT
    } else {
        match decode_frame(pixels, width, height, row_stride, pixel_step) {
            Ok(payload) => {
                import.add(std::str::from_utf8(&payload).expect("the QR decoder returns UTF-8"))
            }
            Err(error) => qr_status(error),
        }
    };
    let (scanned, size) = import.progress();
    // At most MAX_BATCH_SIZE.
    *scanned_out = scanned as u32;
    *size_out = size as u32;
    status
}

/// Reads an export file, an Aegis vault, into an empty import, which is
/// complete afterwards. `password` is null for a plain vault.
/// `ST_PASSWORD_REQUIRED`: the vault is encrypted, ask for its password;
/// `ST_INVALID_CREDENTIALS`: the password opens no slot; `ST_NOT_EXPORT`:
/// no Aegis vault; `ST_UNSUPPORTED_FORMAT`: a vault SailToken cannot read;
/// `ST_LIMIT_EXCEEDED`: a file or key derivation beyond the limits. Runs
/// scrypt for an encrypted vault, so call it off the UI thread.
///
/// # Safety
///
/// `import` must be a live handle not in use by another thread; `data`
/// valid for reads of `length` bytes; `password` null or valid for reads
/// of `password_length` bytes.
#[no_mangle]
pub unsafe extern "C" fn st_import_from_file(
    import: *mut StImport,
    data: *const u8,
    length: usize,
    password: *const u8,
    password_length: usize,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(import), Some(data)) = (unsafe { (import.as_mut(), bytes(data, length)) }) else {
        return ST_INVALID_ARGUMENT;
    };
    if !matches!(import.state, ImportState::Empty) {
        return ST_INVALID_ARGUMENT;
    }
    let password = if password.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller.
        match unsafe { bytes(password, password_length) } {
            Some(password) => Some(password),
            None => return ST_INVALID_ARGUMENT,
        }
    };
    match read_aegis(data, password) {
        Ok(read) => {
            import.state = ImportState::Done {
                import: read,
                size: 1,
            };
            ST_OK
        }
        Err(error) => import_status(error),
    }
}

/// The accounts of a complete import and the entries it skips by reason;
/// `ST_INVALID_ARGUMENT` while codes are missing.
///
/// # Safety
///
/// `import` must be a live handle; `out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn st_import_counts(
    import: *const StImport,
    out: *mut StImportCounts,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(import), Some(out)) = (unsafe { (import.as_ref(), out.as_mut()) }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = StImportCounts::default();
    let Some(import) = import.import() else {
        return ST_INVALID_ARGUMENT;
    };
    out.accounts = import.accounts.len();
    for skipped in &import.skipped {
        match skipped.reason {
            SkipReason::Hotp => out.hotp += 1,
            SkipReason::Unsupported => out.unsupported += 1,
            SkipReason::Invalid => out.invalid += 1,
        }
    }
    ST_OK
}

/// The issuer (`ST_TEXT_ISSUER`) or account name (`ST_TEXT_NAME`) of the
/// account at `index` of a complete import.
///
/// # Safety
///
/// `import` must be a live handle; `out` valid for one write. Release the
/// text with `st_string_free`.
#[no_mangle]
pub unsafe extern "C" fn st_import_text(
    import: *const StImport,
    index: usize,
    column: u32,
    out: *mut StString,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(import), Some(out)) = (unsafe { (import.as_ref(), out.as_mut()) }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = StString::EMPTY;
    let Some(account) = import
        .import()
        .and_then(|import| import.accounts.get(index))
    else {
        return ST_INVALID_ARGUMENT;
    };
    *out = match column {
        ST_TEXT_ISSUER => StString::new(&account.issuer),
        ST_TEXT_NAME => StString::new(&account.account),
        _ => return ST_INVALID_ARGUMENT,
    };
    ST_OK
}

/// Writes 1 for each account of a complete import whose secret an account
/// in the file already has, else 0; `count` must be the number of accounts.
///
/// # Safety
///
/// `database` and `import` must be live handles; `flags_out` valid for
/// writes of `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn st_import_duplicates(
    database: *const StDatabase,
    import: *const StImport,
    flags_out: *mut u8,
    count: usize,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(import)) = (unsafe { (database.as_ref(), import.as_ref()) }) else {
        return ST_INVALID_ARGUMENT;
    };
    let Some(import) = import.import() else {
        return ST_INVALID_ARGUMENT;
    };
    if flags_out.is_null() || count != import.accounts.len() {
        return ST_INVALID_ARGUMENT;
    }
    // SAFETY: flags_out is valid for count bytes, as the caller guarantees.
    let flags = unsafe { slice::from_raw_parts_mut(flags_out, count) };
    flags.fill(0);
    match accounts::duplicates(&database.database, &import.accounts) {
        Ok(duplicates) => {
            for (flag, duplicate) in flags.iter_mut().zip(duplicates) {
                *flag = u8::from(duplicate);
            }
            ST_OK
        }
        Err(error) => kdbx_status(error),
    }
}

/// Adds the accounts of a complete import whose byte in `selected` is not
/// 0, in the export's order; `count` must be the number of accounts.
/// `added_out` gets how many were added, also when an error stops the
/// adding part way, so the caller saves whatever went in.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread; `import`
/// a live handle; `selected` valid for reads of `count` bytes; `added_out`
/// valid for one write.
#[no_mangle]
pub unsafe extern "C" fn st_import_add(
    database: *mut StDatabase,
    import: *const StImport,
    selected: *const u8,
    count: usize,
    now: i64,
    added_out: *mut usize,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(database), Some(import), Some(added_out), Some(selected)) = (unsafe {
        (
            database.as_mut(),
            import.as_ref(),
            added_out.as_mut(),
            bytes(selected, count),
        )
    }) else {
        return ST_INVALID_ARGUMENT;
    };
    *added_out = 0;
    let Some(import) = import.import() else {
        return ST_INVALID_ARGUMENT;
    };
    if count != import.accounts.len() {
        return ST_INVALID_ARGUMENT;
    }
    for (account, &chosen) in import.accounts.iter().zip(selected) {
        if chosen == 0 {
            continue;
        }
        if let Err(error) = accounts::add(
            &mut database.database,
            &account.issuer,
            &account.account,
            &account.settings,
            now,
        ) {
            return super::account_status(error);
        }
        *added_out += 1;
    }
    ST_OK
}

/// Releases an import and wipes the secrets it holds.
///
/// # Safety
///
/// `import` must be null or a handle from `st_import_new` that has not been
/// freed.
#[no_mangle]
pub unsafe extern "C" fn st_import_free(import: *mut StImport) {
    if !import.is_null() {
        // SAFETY: the handle came from Box::into_raw in st_import_new.
        drop(unsafe { Box::from_raw(import) });
    }
}
