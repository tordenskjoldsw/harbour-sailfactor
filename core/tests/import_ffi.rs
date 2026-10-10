//! The import through the C API, as the bridge drives it: camera frames
//! with export codes rendered from `fixtures/qr` (`tools/gen-qr-fixtures.sh`).

use std::path::PathBuf;
use std::ptr;

use sailtoken_core::ffi::accounts::{
    st_account_list, st_account_list_free, st_account_list_length,
};
use sailtoken_core::ffi::database::{st_database_free, st_database_open};
use sailtoken_core::ffi::import::{
    st_import_add, st_import_counts, st_import_duplicates, st_import_free, st_import_from_frame,
    st_import_new, st_import_text,
};
use sailtoken_core::ffi::pending::{st_pending_free, st_pending_from_frame};
use sailtoken_core::ffi::{
    st_string_free, StDatabase, StImport, StImportCounts, StString, ST_ALREADY_SCANNED,
    ST_EXPORT_CODE, ST_INVALID_ARGUMENT, ST_NOT_EXPORT, ST_NOT_FOUND, ST_OK, ST_TEXT_ISSUER,
    ST_TEXT_NAME,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/totp-entries.kdbx");
const PASSWORD: &[u8] = b"sailvault-fixture";
const NOW: i64 = 1_790_000_000;
const MODULE: usize = 4;
const QUIET_ZONE: usize = 4;

/// A frame with the fixture's code, unrotated, dark on light.
fn frame(name: &str) -> (Vec<u8>, u32) {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/fixtures/qr", name]
        .iter()
        .collect();
    let modules: Vec<Vec<bool>> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| line.chars().map(|module| module == '#').collect())
        .collect();
    let side = (modules.len() + 2 * QUIET_ZONE) * MODULE;
    let mut pixels = vec![235u8; side * side];
    for (row, line) in modules.iter().enumerate() {
        for (column, &dark) in line.iter().enumerate() {
            if !dark {
                continue;
            }
            for y in 0..MODULE {
                let start =
                    ((row + QUIET_ZONE) * MODULE + y) * side + (column + QUIET_ZONE) * MODULE;
                pixels[start..start + MODULE].fill(20);
            }
        }
    }
    (pixels, side as u32)
}

fn scan(import: *mut StImport, name: &str) -> (i32, u32, u32) {
    let (pixels, side) = frame(name);
    let (mut scanned, mut size) = (u32::MAX, u32::MAX);
    // SAFETY: import is live; pixels is a live slice of side * side bytes.
    let status = unsafe {
        st_import_from_frame(
            import,
            pixels.as_ptr(),
            pixels.len(),
            side,
            side,
            side,
            1,
            &mut scanned,
            &mut size,
        )
    };
    (status, scanned, size)
}

fn text(import: *const StImport, index: usize, column: u32) -> String {
    let mut string = StString::EMPTY;
    // SAFETY: import is live; string is a local.
    assert_eq!(
        unsafe { st_import_text(import, index, column, &mut string) },
        ST_OK
    );
    // SAFETY: a non-null string holds length bytes owned by the core.
    let value = if string.data.is_null() {
        String::new()
    } else {
        String::from_utf8(
            unsafe { std::slice::from_raw_parts(string.data, string.length) }.to_vec(),
        )
        .unwrap()
    };
    // SAFETY: the string came from the core and is not used afterwards.
    unsafe { st_string_free(string) };
    value
}

fn open_fixture() -> *mut StDatabase {
    let mut database = ptr::null_mut();
    // SAFETY: all inputs are live slices; database is a local.
    let status = unsafe {
        st_database_open(
            FIXTURE.as_ptr(),
            FIXTURE.len(),
            PASSWORD.as_ptr(),
            PASSWORD.len(),
            true,
            ptr::null(),
            0,
            &mut database,
        )
    };
    assert_eq!(status, ST_OK);
    database
}

fn duplicates(database: *const StDatabase, import: *const StImport) -> Vec<u8> {
    let mut flags = vec![9u8; 2];
    // SAFETY: both handles are live; flags holds two bytes.
    let status = unsafe { st_import_duplicates(database, import, flags.as_mut_ptr(), flags.len()) };
    assert_eq!(status, ST_OK);
    flags
}

fn account_count(database: *const StDatabase) -> usize {
    let mut list = ptr::null_mut();
    // SAFETY: database is live; list is a local, freed below.
    unsafe {
        assert_eq!(st_account_list(database, &mut list), ST_OK);
        let length = st_account_list_length(list);
        st_account_list_free(list);
        length
    }
}

#[test]
fn the_account_scanner_hands_export_codes_to_the_import() {
    let (pixels, side) = frame("export-1-of-2.txt");
    let mut pending = ptr::null_mut();
    // SAFETY: pixels is a live slice of side * side bytes; pending a local.
    let status = unsafe {
        st_pending_from_frame(
            pixels.as_ptr(),
            pixels.len(),
            side,
            side,
            side,
            1,
            &mut pending,
        )
    };

    assert_eq!(status, ST_EXPORT_CODE);
    assert!(pending.is_null());
    // SAFETY: null is accepted.
    unsafe { st_pending_free(pending) };
}

#[test]
fn collects_an_export_and_adds_the_chosen_accounts() {
    let import = st_import_new();
    let database = open_fixture();
    let before = account_count(database);

    assert_eq!(scan(import, "totp.txt"), (ST_NOT_EXPORT, 0, 0));
    assert_eq!(scan(import, "export-2-of-2.txt"), (ST_OK, 1, 2));
    assert_eq!(
        scan(import, "export-2-of-2.txt"),
        (ST_ALREADY_SCANNED, 1, 2)
    );
    let mut counts = StImportCounts::default();
    // SAFETY: import is live; counts is a local.
    assert_eq!(
        unsafe { st_import_counts(import, &mut counts) },
        ST_INVALID_ARGUMENT
    );
    assert_eq!(scan(import, "export-1-of-2.txt"), (ST_OK, 2, 2));

    // SAFETY: import is live; counts is a local.
    assert_eq!(unsafe { st_import_counts(import, &mut counts) }, ST_OK);
    assert_eq!(
        counts,
        StImportCounts {
            accounts: 2,
            hotp: 1,
            unsupported: 0,
            invalid: 0
        }
    );
    assert_eq!(text(import, 0, ST_TEXT_ISSUER), "Example");
    assert_eq!(text(import, 0, ST_TEXT_NAME), "alice@example.org");
    assert_eq!(text(import, 1, ST_TEXT_ISSUER), "Other");
    assert_eq!(text(import, 1, ST_TEXT_NAME), "bob");

    // The fixture has alice's secret, not bob's.
    assert_eq!(duplicates(database, import), [1, 0]);
    let mut added = usize::MAX;
    // SAFETY: both handles are live; the selection holds two bytes.
    let status = unsafe { st_import_add(database, import, [0u8, 1].as_ptr(), 2, NOW, &mut added) };
    assert_eq!((status, added), (ST_OK, 1));
    assert_eq!(account_count(database), before + 1);
    assert_eq!(duplicates(database, import), [1, 1]);

    // SAFETY: both handles are live and not used afterwards.
    unsafe {
        st_import_free(import);
        st_database_free(database);
    }
}

#[test]
fn reports_frames_without_a_code_and_wrong_arguments() {
    let import = st_import_new();
    let pixels = vec![235u8; 64 * 64];
    let (mut scanned, mut size) = (0, 0);
    // SAFETY: import is live; pixels is a live slice of 64 * 64 bytes.
    let status = unsafe {
        st_import_from_frame(
            import,
            pixels.as_ptr(),
            pixels.len(),
            64,
            64,
            64,
            1,
            &mut scanned,
            &mut size,
        )
    };
    assert_eq!(status, ST_NOT_FOUND);

    let mut added = 0;
    // SAFETY: import is live; an incomplete import refuses to add.
    let status = unsafe { st_import_add(ptr::null_mut(), import, ptr::null(), 0, NOW, &mut added) };
    assert_eq!(status, ST_INVALID_ARGUMENT);

    // SAFETY: import is live and not used afterwards; null is accepted.
    unsafe {
        st_import_free(import);
        st_import_free(ptr::null_mut());
    }
}
