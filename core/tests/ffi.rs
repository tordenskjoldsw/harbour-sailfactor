//! The C API end to end, as the C++ bridge uses it.

use std::ptr;

use sailfactor_core::ffi::accounts::{
    sf_account_add, sf_account_code, sf_account_delete, sf_account_list, sf_account_list_free,
    sf_account_list_has_password, sf_account_list_kind, sf_account_list_length,
    sf_account_list_text, sf_account_list_uuid, sf_account_rename,
};
use sailfactor_core::ffi::database::{
    sf_database_create, sf_database_free, sf_database_from_kdbx3, sf_database_merge,
    sf_database_open, sf_database_open_like, sf_database_save, sf_database_set_kdf_level,
    sf_kdbx_version,
};
use sailfactor_core::ffi::pending::{
    sf_pending_code, sf_pending_free, sf_pending_from_secret, sf_pending_from_uri, sf_pending_text,
};
use sailfactor_core::ffi::sync::{sf_database_set_sync_settings, sf_database_sync_setting};
use sailfactor_core::ffi::{
    sf_bytes_free, sf_string_free, SfAccountList, SfBytes, SfDatabase, SfMergeChanges, SfPending,
    SfString, SF_ALGORITHM_SHA256, SF_ENCODER_DECIMAL, SF_ENCODER_STEAM, SF_HOTP,
    SF_INVALID_ARGUMENT, SF_INVALID_CREDENTIALS, SF_INVALID_SECRET, SF_INVALID_SETTINGS,
    SF_KDF_STANDARD, SF_KIND_HOTP, SF_KIND_NO_CODE, SF_KIND_TOTP, SF_NOT_FOUND, SF_NOT_KDBX,
    SF_NOT_OTPAUTH, SF_NO_CODE, SF_OK, SF_SYNC_APP_PASSWORD, SF_SYNC_CERTIFICATE, SF_SYNC_PATH,
    SF_SYNC_SERVER, SF_SYNC_USER, SF_TEXT_ISSUER, SF_TEXT_NAME, SF_UUID_LENGTH,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/totp-entries.kdbx");
const KDBX31: &[u8] = include_bytes!("fixtures/kdbx31-aeskdf.kdbx");
const PASSWORD: &[u8] = b"sailvault-fixture";
const NOW: i64 = 1_790_000_000;
const EXAMPLE_URI: &str =
    "otpauth://totp/Example:new@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Example";

/// Takes a string from the core and releases it.
fn take(string: SfString) -> String {
    let text = if string.data.is_null() {
        String::new()
    } else {
        // SAFETY: a non-null string holds length bytes owned by the core.
        let bytes = unsafe { std::slice::from_raw_parts(string.data, string.length) };
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    // SAFETY: the string came from the core and is not used afterwards.
    unsafe { sf_string_free(string) };
    text
}

fn open(data: &[u8], password: &[u8]) -> Result<*mut SfDatabase, i32> {
    let mut database = ptr::null_mut();
    // SAFETY: all inputs are live slices; database is a local.
    let status = unsafe {
        sf_database_open(
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
    if status == SF_OK {
        Ok(database)
    } else {
        assert!(database.is_null());
        Err(status)
    }
}

struct Row {
    uuid: [u8; SF_UUID_LENGTH],
    issuer: String,
    name: String,
    kind: (u32, u32, u32, u32),
}

fn rows(database: *const SfDatabase) -> Vec<Row> {
    let mut list: *mut SfAccountList = ptr::null_mut();
    // SAFETY: database is live and list a local.
    assert_eq!(unsafe { sf_account_list(database, &mut list) }, SF_OK);
    // SAFETY: list is live until freed below.
    let length = unsafe { sf_account_list_length(list) };
    let rows = (0..length)
        .map(|index| {
            let mut uuid = [0u8; SF_UUID_LENGTH];
            let (mut issuer, mut name) = (SfString::EMPTY, SfString::EMPTY);
            let mut kind = (0, 0, 0, 0);
            // SAFETY: index is in range and every output is a local.
            unsafe {
                assert_eq!(sf_account_list_uuid(list, index, uuid.as_mut_ptr()), SF_OK);
                assert_eq!(
                    sf_account_list_text(list, index, SF_TEXT_ISSUER, &mut issuer),
                    SF_OK
                );
                assert_eq!(
                    sf_account_list_text(list, index, SF_TEXT_NAME, &mut name),
                    SF_OK
                );
                assert_eq!(
                    sf_account_list_kind(
                        list,
                        index,
                        &mut kind.0,
                        &mut kind.1,
                        &mut kind.2,
                        &mut kind.3
                    ),
                    SF_OK
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
        let mut out = SfString::EMPTY;
        assert_eq!(
            sf_account_list_text(list, length, SF_TEXT_NAME, &mut out),
            SF_NOT_FOUND
        );
        sf_account_list_free(list);
    }
    rows
}

fn code(
    database: *const SfDatabase,
    uuid: &[u8; SF_UUID_LENGTH],
    now: i64,
) -> Result<(String, u32), i32> {
    let mut code = SfString::EMPTY;
    let mut remaining = 0;
    // SAFETY: database is live, uuid holds 16 bytes, outputs are locals.
    let status =
        unsafe { sf_account_code(database, uuid.as_ptr(), now, &mut code, &mut remaining) };
    let code = take(code);
    if status == SF_OK {
        Ok((code, remaining))
    } else {
        Err(status)
    }
}

fn pending_from_uri(uri: &str) -> Result<*mut SfPending, i32> {
    let mut pending = ptr::null_mut();
    // SAFETY: uri is a live string; pending is a local.
    let status = unsafe { sf_pending_from_uri(uri.as_ptr(), uri.len(), &mut pending) };
    if status == SF_OK {
        Ok(pending)
    } else {
        Err(status)
    }
}

#[test]
fn opening_needs_the_right_password() {
    assert_eq!(
        open(FIXTURE, b"wrong").map(|_| ()),
        Err(SF_INVALID_CREDENTIALS)
    );
    let database = open(FIXTURE, PASSWORD).unwrap();
    // SAFETY: the handle is freed once.
    unsafe { sf_database_free(database) };
    // SAFETY: null handles are ignored.
    unsafe { sf_database_free(ptr::null_mut()) };
}

#[test]
fn lists_accounts_with_their_kind_and_codes() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let rows = rows(database);
    assert_eq!(rows.len(), 12);
    let row = |issuer: &str| rows.iter().find(|row| row.issuer == issuer).unwrap();
    let first = row("SHA-1 six digits");
    assert_eq!(first.name, "alice@example.org");
    assert_eq!(first.kind, (SF_KIND_TOTP, 6, 30, SF_ENCODER_DECIMAL));
    assert_eq!(row("Steam").kind, (SF_KIND_TOTP, 5, 30, SF_ENCODER_STEAM));
    assert_eq!(row("Counter based").kind, (SF_KIND_HOTP, 0, 0, 0));
    assert_eq!(row("No code").kind, (SF_KIND_NO_CODE, 0, 0, 0));

    let (code_at_59, remaining) = code(database, &first.uuid, 59).unwrap();
    assert_eq!((code_at_59.len(), remaining), (6, 1));
    assert_eq!(code(database, &row("No code").uuid, NOW), Err(SF_NO_CODE));
    assert_eq!(code(database, &first.uuid, -1), Err(SF_INVALID_ARGUMENT));
    assert_eq!(
        code(database, &[0xee; SF_UUID_LENGTH], NOW),
        Err(SF_NOT_FOUND)
    );
    // SAFETY: the handle is freed once.
    unsafe { sf_database_free(database) };
}

#[test]
fn a_pending_account_shows_its_code_and_is_added() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let pending = pending_from_uri(EXAMPLE_URI).unwrap();
    let (mut issuer, mut name, mut first_code) =
        (SfString::EMPTY, SfString::EMPTY, SfString::EMPTY);
    let mut remaining = 0;
    // SAFETY: pending is live and every output a local.
    unsafe {
        assert_eq!(sf_pending_text(pending, SF_TEXT_ISSUER, &mut issuer), SF_OK);
        assert_eq!(sf_pending_text(pending, SF_TEXT_NAME, &mut name), SF_OK);
        assert_eq!(
            sf_pending_code(pending, 59, &mut first_code, &mut remaining),
            SF_OK
        );
    }
    assert_eq!(
        (take(issuer).as_str(), take(name).as_str()),
        ("Example", "new@example.org")
    );
    let first_code = take(first_code);

    let (issuer, name) = ("Edited issuer", "edited@example.org");
    let mut uuid = [0u8; SF_UUID_LENGTH];
    // SAFETY: database and pending are live; strings and uuid are locals.
    let status = unsafe {
        sf_account_add(
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
    assert_eq!(status, SF_OK);
    // SAFETY: the pending handle is freed once.
    unsafe { sf_pending_free(pending) };

    let mut file = SfBytes::EMPTY;
    // SAFETY: database is live and file a local.
    assert_eq!(unsafe { sf_database_save(database, &mut file) }, SF_OK);
    // SAFETY: file holds length bytes until freed below.
    let saved = unsafe { std::slice::from_raw_parts(file.data, file.length) }.to_vec();
    // SAFETY: each handle and file is freed once.
    unsafe {
        sf_bytes_free(file);
        sf_database_free(database);
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
            sf_account_rename(
                reopened,
                uuid.as_ptr(),
                renamed.as_ptr(),
                renamed.len(),
                name.as_ptr(),
                name.len(),
                NOW,
                &mut changed,
            ),
            SF_OK
        );
        assert_eq!(
            sf_account_delete(reopened, uuid.as_ptr(), NOW, &mut permanent),
            SF_OK
        );
    }
    assert!(changed);
    assert!(!permanent, "the first delete goes to the recycle bin");
    assert!(rows(reopened).iter().all(|row| row.uuid != uuid));
    // SAFETY: the handle is freed once.
    unsafe { sf_database_free(reopened) };
}

#[test]
fn pending_accounts_report_what_is_wrong() {
    assert_eq!(
        pending_from_uri("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP").map(|_| ()),
        Err(SF_HOTP)
    );
    assert_eq!(
        pending_from_uri("https://example.org").map(|_| ()),
        Err(SF_NOT_OTPAUTH)
    );
    let typed = |secret: &str, digits: u32, period: u32| {
        let mut pending = ptr::null_mut();
        // SAFETY: secret is a live string; pending is a local.
        let status = unsafe {
            sf_pending_from_secret(
                secret.as_ptr(),
                secret.len(),
                SF_ALGORITHM_SHA256,
                digits,
                period,
                SF_ENCODER_DECIMAL,
                &mut pending,
            )
        };
        // SAFETY: a pending handle, if any, is freed once.
        unsafe { sf_pending_free(pending) };
        status
    };
    assert_eq!(typed("JBSW Y3DP EHPK 3PXP", 8, 60), SF_OK);
    assert_eq!(typed("not base32!", 6, 30), SF_INVALID_SECRET);
    assert_eq!(typed("JBSWY3DPEHPK3PXP", 300, 30), SF_INVALID_SETTINGS);
    assert_eq!(typed("JBSWY3DPEHPK3PXP", 6, 0), SF_INVALID_SETTINGS);
    let mut pending = ptr::null_mut();
    let secret = "JBSWY3DPEHPK3PXP";
    // SAFETY: an unknown algorithm is refused before anything is written.
    let status = unsafe {
        sf_pending_from_secret(
            secret.as_ptr(),
            secret.len(),
            9,
            6,
            30,
            SF_ENCODER_DECIMAL,
            &mut pending,
        )
    };
    assert_eq!((status, pending.is_null()), (SF_INVALID_ARGUMENT, true));
}

#[test]
fn a_created_file_opens_with_its_password() {
    let password = b"correct horse battery staple";
    let name = "Authenticator";
    let mut database = ptr::null_mut();
    let mut file = SfBytes::EMPTY;
    // SAFETY: inputs are live slices; outputs are locals.
    let status = unsafe {
        sf_database_create(
            password.as_ptr(),
            password.len(),
            name.as_ptr(),
            name.len(),
            SF_KDF_STANDARD,
            NOW,
            &mut database,
            &mut file,
        )
    };
    assert_eq!(status, SF_OK);
    assert!(rows(database).is_empty());
    // SAFETY: file holds length bytes until freed below.
    let saved = unsafe { std::slice::from_raw_parts(file.data, file.length) }.to_vec();
    // SAFETY: each is freed once.
    unsafe {
        sf_bytes_free(file);
        sf_database_free(database);
    }
    let reopened = open(&saved, password).unwrap();
    assert!(rows(reopened).is_empty());
    // SAFETY: the handle is freed once.
    unsafe { sf_database_free(reopened) };

    let mut refused = ptr::null_mut();
    let mut no_file = SfBytes::EMPTY;
    // SAFETY: an empty password is refused before anything is written.
    let status = unsafe {
        sf_database_create(
            ptr::null(),
            0,
            name.as_ptr(),
            name.len(),
            SF_KDF_STANDARD,
            NOW,
            &mut refused,
            &mut no_file,
        )
    };
    assert_eq!(
        (status, refused.is_null(), no_file.data.is_null()),
        (SF_INVALID_ARGUMENT, true, true)
    );
}

fn version(data: &[u8]) -> Result<(u16, u16), i32> {
    let (mut major, mut minor) = (7, 7);
    // SAFETY: data is a live slice; major and minor are locals.
    let status = unsafe { sf_kdbx_version(data.as_ptr(), data.len(), &mut major, &mut minor) };
    if status == SF_OK {
        Ok((major, minor))
    } else {
        assert_eq!((major, minor), (0, 0), "outputs are cleared on an error");
        Err(status)
    }
}

fn from_kdbx3(database: *const SfDatabase) -> bool {
    let mut from_kdbx3 = true;
    // SAFETY: database is live; from_kdbx3 is a local.
    assert_eq!(
        unsafe { sf_database_from_kdbx3(database, &mut from_kdbx3) },
        SF_OK
    );
    from_kdbx3
}

#[test]
fn the_format_version_is_read_from_the_file_start() {
    assert_eq!(version(FIXTURE).map(|(major, _)| major), Ok(4));
    assert_eq!(version(&KDBX31[..12]), Ok((3, 1)));
    assert_eq!(version(b"not a keepass file"), Err(SF_NOT_KDBX));
    assert_eq!(version(&FIXTURE[..11]), Err(SF_NOT_KDBX));
}

#[test]
fn a_kdbx3_file_is_saved_as_kdbx4_with_argon2id() {
    let database = open(KDBX31, PASSWORD).unwrap();
    assert!(from_kdbx3(database));
    // SAFETY: database is live and used by this thread only.
    assert_eq!(
        unsafe { sf_database_set_kdf_level(database, 7) },
        SF_INVALID_ARGUMENT
    );
    // SAFETY: as above.
    assert_eq!(
        unsafe { sf_database_set_kdf_level(database, SF_KDF_STANDARD) },
        SF_OK
    );
    let mut file = SfBytes::EMPTY;
    // SAFETY: database is live; file is a local.
    assert_eq!(unsafe { sf_database_save(database, &mut file) }, SF_OK);
    // SAFETY: file holds length bytes until freed below.
    let saved = unsafe { std::slice::from_raw_parts(file.data, file.length) }.to_vec();
    // SAFETY: each is freed once.
    unsafe {
        sf_bytes_free(file);
        sf_database_free(database);
    }
    assert_eq!(version(&saved).map(|(major, _)| major), Ok(4));
    let reopened = open(&saved, PASSWORD).unwrap();
    assert!(!from_kdbx3(reopened));
    // SAFETY: the handle is freed once.
    unsafe { sf_database_free(reopened) };
}

#[test]
fn another_copy_opens_with_the_held_key_and_merges() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let mut copy = ptr::null_mut();
    // SAFETY: database is live; the inputs are live slices; copy is a local.
    unsafe {
        assert_eq!(
            sf_database_open_like(database, b"no".as_ptr(), 2, &mut copy),
            SF_NOT_KDBX
        );
        assert!(copy.is_null());
        assert_eq!(
            sf_database_open_like(database, FIXTURE.as_ptr(), FIXTURE.len(), &mut copy),
            SF_OK
        );
    }
    let mut changes = SfMergeChanges {
        added: 9,
        modified: 9,
        moved: 9,
        deleted: 9,
        metadata: true,
    };
    // SAFETY: both handles are live and used by this thread only.
    assert_eq!(
        unsafe { sf_database_merge(database, copy, &mut changes) },
        SF_OK
    );
    assert_eq!(
        changes,
        SfMergeChanges::default(),
        "an identical copy changes nothing"
    );
    // SAFETY: as above; merging a handle into itself is refused.
    assert_eq!(
        unsafe { sf_database_merge(database, database, &mut changes) },
        SF_INVALID_ARGUMENT
    );
    // SAFETY: each is freed once.
    unsafe {
        sf_database_free(copy);
        sf_database_free(database);
    }
}

#[test]
fn sync_settings_round_trip_and_stay_out_of_the_account_list() {
    let database = open(FIXTURE, PASSWORD).unwrap();
    let accounts = rows(database).len();
    let mut value = SfString::EMPTY;
    // SAFETY: database is live; value is a local.
    assert_eq!(
        unsafe { sf_database_sync_setting(database, SF_SYNC_SERVER, &mut value) },
        SF_NOT_FOUND
    );
    let fields = [
        "https://cloud.example.org",
        "alice",
        "app-password",
        "/SailFactor/SailFactor.kdbx",
    ];
    let mut uuid = [7u8; SF_UUID_LENGTH];
    // SAFETY: every string is a live slice; database is used by this thread
    // only; uuid is a local of 16 bytes.
    let status = unsafe {
        sf_database_set_sync_settings(
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
    assert_eq!(status, SF_OK);
    assert_ne!(uuid, [0u8; SF_UUID_LENGTH]);
    for (setting, expected) in [
        (SF_SYNC_SERVER, fields[0]),
        (SF_SYNC_USER, fields[1]),
        (SF_SYNC_APP_PASSWORD, fields[2]),
        (SF_SYNC_PATH, fields[3]),
        (SF_SYNC_CERTIFICATE, ""),
    ] {
        let mut value = SfString::EMPTY;
        // SAFETY: as above.
        assert_eq!(
            unsafe { sf_database_sync_setting(database, setting, &mut value) },
            SF_OK
        );
        assert_eq!(take(value), expected);
    }
    // SAFETY: as above.
    assert_eq!(
        unsafe { sf_database_sync_setting(database, 9, &mut value) },
        SF_INVALID_ARGUMENT
    );
    assert_eq!(
        rows(database).len(),
        accounts,
        "the sync entry is no account"
    );
    assert!(rows(database).iter().all(|row| row.uuid != uuid));
    // SAFETY: the handle is freed once.
    unsafe { sf_database_free(database) };
}

#[test]
fn the_list_says_which_entries_store_a_password() {
    const LOGINS: &[u8] = include_bytes!("fixtures/kdbx4-aes-aeskdf.kdbx");
    let database = open(LOGINS, PASSWORD).unwrap();
    let mut list: *mut SfAccountList = ptr::null_mut();
    // SAFETY: database is live and list a local.
    assert_eq!(unsafe { sf_account_list(database, &mut list) }, SF_OK);
    // SAFETY: list is live until freed below.
    let length = unsafe { sf_account_list_length(list) };
    let flags: Vec<bool> = (0..length)
        .map(|index| {
            let mut has_password = false;
            // SAFETY: list is live; has_password is a local.
            assert_eq!(
                unsafe { sf_account_list_has_password(list, index, &mut has_password) },
                SF_OK
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
        unsafe { sf_account_list_has_password(list, length, &mut has_password) },
        SF_NOT_FOUND
    );
    assert!(!has_password);
    // SAFETY: each is freed once.
    unsafe {
        sf_account_list_free(list);
        sf_database_free(database);
    }
}
