//! The C API end to end, as the C++ bridge uses it.

use std::ptr;

use sailtoken_core::ffi::accounts::{
    st_account_add, st_account_code, st_account_delete, st_account_list, st_account_list_free,
    st_account_list_has_password, st_account_list_kind, st_account_list_length,
    st_account_list_text, st_account_list_uuid, st_account_rename, st_database_empty_recycle_bin,
    st_database_recycle_bin_items,
};
use sailtoken_core::ffi::database::{
    st_database_create, st_database_free, st_database_from_kdbx3, st_database_merge,
    st_database_open, st_database_open_like, st_database_save, st_database_set_kdf_level,
    st_kdbx_version,
};
use sailtoken_core::ffi::pending::{
    st_pending_code, st_pending_free, st_pending_from_secret, st_pending_from_uri, st_pending_text,
};
use sailtoken_core::ffi::sync::{st_database_set_sync_settings, st_database_sync_setting};
use sailtoken_core::ffi::{
    st_bytes_free, st_string_free, StAccountList, StBytes, StDatabase, StMergeChanges, StPending,
    StString, ST_ALGORITHM_SHA256, ST_ENCODER_DECIMAL, ST_ENCODER_STEAM, ST_HOTP,
    ST_INVALID_ARGUMENT, ST_INVALID_CREDENTIALS, ST_INVALID_SECRET, ST_INVALID_SETTINGS,
    ST_KDF_STANDARD, ST_KIND_HOTP, ST_KIND_NO_CODE, ST_KIND_TOTP, ST_NOT_FOUND, ST_NOT_KDBX,
    ST_NOT_OTPAUTH, ST_NO_CODE, ST_OK, ST_SYNC_APP_PASSWORD, ST_SYNC_CERTIFICATE, ST_SYNC_PATH,
    ST_SYNC_SERVER, ST_SYNC_USER, ST_TEXT_ISSUER, ST_TEXT_NAME, ST_UUID_LENGTH,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/totp-entries.kdbx");
const KDBX31: &[u8] = include_bytes!("fixtures/kdbx31-aeskdf.kdbx");
const PASSWORD: &[u8] = b"sailvault-fixture";
const NOW: i64 = 1_790_000_000;
const EXAMPLE_URI: &str =
    "otpauth://totp/Example:new@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Example";

/// Takes a string from the core and releases it.
fn take(string: StString) -> String {
    let text = if string.data.is_null() {
        String::new()
    } else {
        // SAFETY: a non-null string holds length bytes owned by the core.
        let bytes = unsafe { std::slice::from_raw_parts(string.data, string.length) };
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    // SAFETY: the string came from the core and is not used afterwards.
    unsafe { st_string_free(string) };
    text
}

fn open(data: &[u8], password: &[u8]) -> Result<*mut StDatabase, i32> {
    let mut database = ptr::null_mut();
    // SAFETY: all inputs are live slices; database is a local.
    let status = unsafe {
        st_database_open(
            data.as_ptr(),
            data.len(),
            password.as_ptr(),
            password.len(),
            true,
            ptr::null(),
            0,
            &mut database,
        )
    };
    if status == ST_OK {
        Ok(database)
    } else {
        assert!(database.is_null());
        Err(status)
    }
}

struct Row {
    uuid: [u8; ST_UUID_LENGTH],
    issuer: String,
    name: String,
    kind: (u32, u32, u32, u32),
}

fn rows(database: *const StDatabase) -> Vec<Row> {
    let mut list: *mut StAccountList = ptr::null_mut();
    // SAFETY: database is live and list a local.
    assert_eq!(unsafe { st_account_list(database, &mut list) }, ST_OK);
    // SAFETY: list is live until freed below.
    let length = unsafe { st_account_list_length(list) };
    let rows = (0..length)
        .map(|index| {
            let mut uuid = [0u8; ST_UUID_LENGTH];
            let (mut issuer, mut name) = (StString::EMPTY, StString::EMPTY);
            let mut kind = (0, 0, 0, 0);
            // SAFETY: index is in range and every output is a local.
            unsafe {
                assert_eq!(st_account_list_uuid(list, index, uuid.as_mut_ptr()), ST_OK);
                assert_eq!(
                    st_account_list_text(list, index, ST_TEXT_ISSUER, &mut issuer),
                    ST_OK
                );
                assert_eq!(
                    st_account_list_text(list, index, ST_TEXT_NAME, &mut name),
                    ST_OK
                );
                assert_eq!(
                    st_account_list_kind(
                        list,
                        index,
                        &mut kind.0,
                        &mut kind.1,
                        &mut kind.2,
                        &mut kind.3
                    ),
                    ST_OK
                );
            }
            Row {
                uuid,
                issuer: take(issuer),
                name: take(name),
                kind,
            }
        })
        .collect();
    // SAFETY: the list index is past the end; the list is freed once.
    unsafe {
        let mut out = StString::EMPTY;
        assert_eq!(
            st_account_list_text(list, length, ST_TEXT_NAME, &mut out),
            ST_NOT_FOUND
        );
        st_account_list_free(list);
    }
    rows
}

fn code(
    database: *const StDatabase,
    uuid: &[u8; ST_UUID_LENGTH],
    now: i64,
) -> Result<(String, u32), i32> {
    let mut code = StString::EMPTY;
    let mut remaining = 0;
    // SAFETY: database is live, uuid holds 16 bytes, outputs are locals.
    let status =
        unsafe { st_account_code(database, uuid.as_ptr(), now, &mut code, &mut remaining) };
    let code = take(code);
    if status == ST_OK {
        Ok((code, remaining))
    } else {
        Err(status)
    }
}

fn pending_from_uri(uri: &str) -> Result<*mut StPending, i32> {
    let mut pending = ptr::null_mut();
    // SAFETY: uri is a live string; pending is a local.
    let status = unsafe { st_pending_from_uri(uri.as_ptr(), uri.len(), &mut pending) };
    if status == ST_OK {
        Ok(pending)
    } else {
        Err(status)
    }
}

#[test]
fn opening_needs_the_right_password() {
    assert_eq!(
        open(FIXTURE, b"wrong").map(|_| ()),
        Err(ST_INVALID_CREDENTIALS)
    );
    let database = open(FIXTURE, PASSWORD).unwrap();
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(database) };
    // SAFETY: null handles are ignored.
    unsafe { st_database_free(ptr::null_mut()) };
}

#[test]
fn lists_accounts_with_their_kind_and_codes() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let rows = rows(database);
    assert_eq!(rows.len(), 12);
    let row = |issuer: &str| rows.iter().find(|row| row.issuer == issuer).unwrap();
    let first = row("SHA-1 six digits");
    assert_eq!(first.name, "alice@example.org");
    assert_eq!(first.kind, (ST_KIND_TOTP, 6, 30, ST_ENCODER_DECIMAL));
    assert_eq!(row("Steam").kind, (ST_KIND_TOTP, 5, 30, ST_ENCODER_STEAM));
    assert_eq!(row("Counter based").kind, (ST_KIND_HOTP, 0, 0, 0));
    assert_eq!(row("No code").kind, (ST_KIND_NO_CODE, 0, 0, 0));

    let (code_at_59, remaining) = code(database, &first.uuid, 59).unwrap();
    assert_eq!((code_at_59.len(), remaining), (6, 1));
    assert_eq!(code(database, &row("No code").uuid, NOW), Err(ST_NO_CODE));
    assert_eq!(code(database, &first.uuid, -1), Err(ST_INVALID_ARGUMENT));
    assert_eq!(
        code(database, &[0xee; ST_UUID_LENGTH], NOW),
        Err(ST_NOT_FOUND)
    );
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(database) };
}

#[test]
fn a_pending_account_shows_its_code_and_is_added() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let pending = pending_from_uri(EXAMPLE_URI).unwrap();
    let (mut issuer, mut name, mut first_code) =
        (StString::EMPTY, StString::EMPTY, StString::EMPTY);
    let mut remaining = 0;
    // SAFETY: pending is live and every output a local.
    unsafe {
        assert_eq!(st_pending_text(pending, ST_TEXT_ISSUER, &mut issuer), ST_OK);
        assert_eq!(st_pending_text(pending, ST_TEXT_NAME, &mut name), ST_OK);
        assert_eq!(
            st_pending_code(pending, 59, &mut first_code, &mut remaining),
            ST_OK
        );
    }
    assert_eq!(
        (take(issuer).as_str(), take(name).as_str()),
        ("Example", "new@example.org")
    );
    let first_code = take(first_code);

    let (issuer, name) = ("Edited issuer", "edited@example.org");
    let mut uuid = [0u8; ST_UUID_LENGTH];
    // SAFETY: database and pending are live; strings and uuid are locals.
    let status = unsafe {
        st_account_add(
            database,
            pending,
            issuer.as_ptr(),
            issuer.len(),
            name.as_ptr(),
            name.len(),
            NOW,
            uuid.as_mut_ptr(),
        )
    };
    assert_eq!(status, ST_OK);
    // SAFETY: the pending handle is freed once.
    unsafe { st_pending_free(pending) };

    let mut file = StBytes::EMPTY;
    // SAFETY: database is live and file a local.
    assert_eq!(unsafe { st_database_save(database, &mut file) }, ST_OK);
    // SAFETY: file holds length bytes until freed below.
    let saved = unsafe { std::slice::from_raw_parts(file.data, file.length) }.to_vec();
    // SAFETY: each handle and file is freed once.
    unsafe {
        st_bytes_free(file);
        st_database_free(database);
    }

    let reopened = open(&saved, PASSWORD).unwrap();
    let added = rows(reopened)
        .into_iter()
        .find(|row| row.uuid == uuid)
        .unwrap();
    assert_eq!((added.issuer.as_str(), added.name.as_str()), (issuer, name));
    assert_eq!(code(reopened, &uuid, 59).unwrap().0, first_code);

    let renamed = "Renamed";
    let mut changed = false;
    let mut permanent = true;
    // SAFETY: reopened is live; strings, uuid and outputs are locals.
    unsafe {
        assert_eq!(
            st_account_rename(
                reopened,
                uuid.as_ptr(),
                renamed.as_ptr(),
                renamed.len(),
                name.as_ptr(),
                name.len(),
                NOW,
                &mut changed,
            ),
            ST_OK
        );
        assert_eq!(
            st_account_delete(reopened, uuid.as_ptr(), NOW, &mut permanent),
            ST_OK
        );
    }
    assert!(changed);
    assert!(!permanent, "the first delete goes to the recycle bin");
    assert!(rows(reopened).iter().all(|row| row.uuid != uuid));
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(reopened) };
}

#[test]
fn pending_accounts_report_what_is_wrong() {
    assert_eq!(
        pending_from_uri("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP").map(|_| ()),
        Err(ST_HOTP)
    );
    assert_eq!(
        pending_from_uri("https://example.org").map(|_| ()),
        Err(ST_NOT_OTPAUTH)
    );
    let typed = |secret: &str, digits: u32, period: u32| {
        let mut pending = ptr::null_mut();
        // SAFETY: secret is a live string; pending is a local.
        let status = unsafe {
            st_pending_from_secret(
                secret.as_ptr(),
                secret.len(),
                ST_ALGORITHM_SHA256,
                digits,
                period,
                ST_ENCODER_DECIMAL,
                &mut pending,
            )
        };
        // SAFETY: a pending handle, if any, is freed once.
        unsafe { st_pending_free(pending) };
        status
    };
    assert_eq!(typed("JBSW Y3DP EHPK 3PXP", 8, 60), ST_OK);
    assert_eq!(typed("not base32!", 6, 30), ST_INVALID_SECRET);
    assert_eq!(typed("JBSWY3DPEHPK3PXP", 300, 30), ST_INVALID_SETTINGS);
    assert_eq!(typed("JBSWY3DPEHPK3PXP", 6, 0), ST_INVALID_SETTINGS);
    let mut pending = ptr::null_mut();
    let secret = "JBSWY3DPEHPK3PXP";
    // SAFETY: an unknown algorithm is refused before anything is written.
    let status = unsafe {
        st_pending_from_secret(
            secret.as_ptr(),
            secret.len(),
            9,
            6,
            30,
            ST_ENCODER_DECIMAL,
            &mut pending,
        )
    };
    assert_eq!((status, pending.is_null()), (ST_INVALID_ARGUMENT, true));
}

#[test]
fn a_created_file_opens_with_its_password() {
    let password = b"correct horse battery staple";
    let name = "Authenticator";
    let mut database = ptr::null_mut();
    let mut file = StBytes::EMPTY;
    // SAFETY: inputs are live slices; outputs are locals.
    let status = unsafe {
        st_database_create(
            password.as_ptr(),
            password.len(),
            name.as_ptr(),
            name.len(),
            ST_KDF_STANDARD,
            NOW,
            &mut database,
            &mut file,
        )
    };
    assert_eq!(status, ST_OK);
    assert!(rows(database).is_empty());
    // SAFETY: file holds length bytes until freed below.
    let saved = unsafe { std::slice::from_raw_parts(file.data, file.length) }.to_vec();
    // SAFETY: each is freed once.
    unsafe {
        st_bytes_free(file);
        st_database_free(database);
    }
    let reopened = open(&saved, password).unwrap();
    assert!(rows(reopened).is_empty());
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(reopened) };

    let mut refused = ptr::null_mut();
    let mut no_file = StBytes::EMPTY;
    // SAFETY: an empty password is refused before anything is written.
    let status = unsafe {
        st_database_create(
            ptr::null(),
            0,
            name.as_ptr(),
            name.len(),
            ST_KDF_STANDARD,
            NOW,
            &mut refused,
            &mut no_file,
        )
    };
    assert_eq!(
        (status, refused.is_null(), no_file.data.is_null()),
        (ST_INVALID_ARGUMENT, true, true)
    );
}

fn version(data: &[u8]) -> Result<(u16, u16), i32> {
    let (mut major, mut minor) = (7, 7);
    // SAFETY: data is a live slice; major and minor are locals.
    let status = unsafe { st_kdbx_version(data.as_ptr(), data.len(), &mut major, &mut minor) };
    if status == ST_OK {
        Ok((major, minor))
    } else {
        assert_eq!((major, minor), (0, 0), "outputs are cleared on an error");
        Err(status)
    }
}

fn from_kdbx3(database: *const StDatabase) -> bool {
    let mut from_kdbx3 = true;
    // SAFETY: database is live; from_kdbx3 is a local.
    assert_eq!(
        unsafe { st_database_from_kdbx3(database, &mut from_kdbx3) },
        ST_OK
    );
    from_kdbx3
}

#[test]
fn the_format_version_is_read_from_the_file_start() {
    assert_eq!(version(FIXTURE).map(|(major, _)| major), Ok(4));
    assert_eq!(version(&KDBX31[..12]), Ok((3, 1)));
    assert_eq!(version(b"not a keepass file"), Err(ST_NOT_KDBX));
    assert_eq!(version(&FIXTURE[..11]), Err(ST_NOT_KDBX));
}

#[test]
fn a_kdbx3_file_is_saved_as_kdbx4_with_argon2id() {
    let database = open(KDBX31, PASSWORD).unwrap();
    assert!(from_kdbx3(database));
    // SAFETY: database is live and used by this thread only.
    assert_eq!(
        unsafe { st_database_set_kdf_level(database, 7) },
        ST_INVALID_ARGUMENT
    );
    // SAFETY: as above.
    assert_eq!(
        unsafe { st_database_set_kdf_level(database, ST_KDF_STANDARD) },
        ST_OK
    );
    let mut file = StBytes::EMPTY;
    // SAFETY: database is live; file is a local.
    assert_eq!(unsafe { st_database_save(database, &mut file) }, ST_OK);
    // SAFETY: file holds length bytes until freed below.
    let saved = unsafe { std::slice::from_raw_parts(file.data, file.length) }.to_vec();
    // SAFETY: each is freed once.
    unsafe {
        st_bytes_free(file);
        st_database_free(database);
    }
    assert_eq!(version(&saved).map(|(major, _)| major), Ok(4));
    let reopened = open(&saved, PASSWORD).unwrap();
    assert!(!from_kdbx3(reopened));
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(reopened) };
}

#[test]
fn another_copy_opens_with_the_held_key_and_merges() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let mut copy = ptr::null_mut();
    // SAFETY: database is live; the inputs are live slices; copy is a local.
    unsafe {
        assert_eq!(
            st_database_open_like(database, b"no".as_ptr(), 2, &mut copy),
            ST_NOT_KDBX
        );
        assert!(copy.is_null());
        assert_eq!(
            st_database_open_like(database, FIXTURE.as_ptr(), FIXTURE.len(), &mut copy),
            ST_OK
        );
    }
    let mut changes = StMergeChanges {
        added: 9,
        modified: 9,
        moved: 9,
        deleted: 9,
        metadata: true,
    };
    // SAFETY: both handles are live and used by this thread only.
    assert_eq!(
        unsafe { st_database_merge(database, copy, &mut changes) },
        ST_OK
    );
    assert_eq!(
        changes,
        StMergeChanges::default(),
        "an identical copy changes nothing"
    );
    // SAFETY: as above; merging a handle into itself is refused.
    assert_eq!(
        unsafe { st_database_merge(database, database, &mut changes) },
        ST_INVALID_ARGUMENT
    );
    // SAFETY: each is freed once.
    unsafe {
        st_database_free(copy);
        st_database_free(database);
    }
}

#[test]
fn sync_settings_round_trip_and_stay_out_of_the_account_list() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let accounts = rows(database).len();
    let mut value = StString::EMPTY;
    // SAFETY: database is live; value is a local.
    assert_eq!(
        unsafe { st_database_sync_setting(database, ST_SYNC_SERVER, &mut value) },
        ST_NOT_FOUND
    );
    let fields = [
        "https://cloud.example.org",
        "alice",
        "app-password",
        "/SailToken/SailToken.kdbx",
    ];
    let mut uuid = [7u8; ST_UUID_LENGTH];
    // SAFETY: every string is a live slice; database is used by this thread
    // only; uuid is a local of 16 bytes.
    let status = unsafe {
        st_database_set_sync_settings(
            database,
            fields[0].as_ptr(),
            fields[0].len(),
            fields[1].as_ptr(),
            fields[1].len(),
            fields[2].as_ptr(),
            fields[2].len(),
            fields[3].as_ptr(),
            fields[3].len(),
            ptr::null(),
            0,
            NOW,
            uuid.as_mut_ptr(),
        )
    };
    assert_eq!(status, ST_OK);
    assert_ne!(uuid, [0u8; ST_UUID_LENGTH]);
    for (setting, expected) in [
        (ST_SYNC_SERVER, fields[0]),
        (ST_SYNC_USER, fields[1]),
        (ST_SYNC_APP_PASSWORD, fields[2]),
        (ST_SYNC_PATH, fields[3]),
        (ST_SYNC_CERTIFICATE, ""),
    ] {
        let mut value = StString::EMPTY;
        // SAFETY: as above.
        assert_eq!(
            unsafe { st_database_sync_setting(database, setting, &mut value) },
            ST_OK
        );
        assert_eq!(take(value), expected);
    }
    // SAFETY: as above.
    assert_eq!(
        unsafe { st_database_sync_setting(database, 9, &mut value) },
        ST_INVALID_ARGUMENT
    );
    assert_eq!(
        rows(database).len(),
        accounts,
        "the sync entry is no account"
    );
    assert!(rows(database).iter().all(|row| row.uuid != uuid));
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(database) };
}

#[test]
fn the_list_says_which_entries_store_a_password() {
    const LOGINS: &[u8] = include_bytes!("fixtures/kdbx4-aes-aeskdf.kdbx");
    let database = open(LOGINS, PASSWORD).unwrap();
    let mut list: *mut StAccountList = ptr::null_mut();
    // SAFETY: database is live and list a local.
    assert_eq!(unsafe { st_account_list(database, &mut list) }, ST_OK);
    // SAFETY: list is live until freed below.
    let length = unsafe { st_account_list_length(list) };
    let flags: Vec<bool> = (0..length)
        .map(|index| {
            let mut has_password = false;
            // SAFETY: list is live; has_password is a local.
            assert_eq!(
                unsafe { st_account_list_has_password(list, index, &mut has_password) },
                ST_OK
            );
            has_password
        })
        .collect();
    assert!(
        flags.iter().any(|&flag| flag),
        "the login fixture has passwords"
    );
    let mut has_password = true;
    // SAFETY: as above; an index past the end is reported and clears the output.
    assert_eq!(
        unsafe { st_account_list_has_password(list, length, &mut has_password) },
        ST_NOT_FOUND
    );
    assert!(!has_password);
    // SAFETY: each is freed once.
    unsafe {
        st_account_list_free(list);
        st_database_free(database);
    }
}

#[test]
fn the_recycle_bin_is_counted_and_emptied() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let items = || {
        let mut items = 9;
        // SAFETY: database is live; items is a local.
        assert_eq!(
            unsafe { st_database_recycle_bin_items(database, &mut items) },
            ST_OK
        );
        items
    };
    assert_eq!(items(), 0);
    let uuid = rows(database)[0].uuid;
    let mut permanent = true;
    // SAFETY: database is used by this thread only; uuid and permanent are locals.
    assert_eq!(
        unsafe { st_account_delete(database, uuid.as_ptr(), NOW, &mut permanent) },
        ST_OK
    );
    assert!(!permanent);
    assert_eq!(items(), 1);
    let mut changed = false;
    // SAFETY: as above.
    assert_eq!(
        unsafe { st_database_empty_recycle_bin(database, NOW, &mut changed) },
        ST_OK
    );
    assert!(changed);
    assert_eq!(items(), 0);
    // SAFETY: as above; an empty bin changes nothing.
    assert_eq!(
        unsafe { st_database_empty_recycle_bin(database, NOW, &mut changed) },
        ST_OK
    );
    assert!(!changed);
    // SAFETY: the handle is freed once.
    unsafe { st_database_free(database) };
}
