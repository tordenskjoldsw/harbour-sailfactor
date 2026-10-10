//! Reading Google Authenticator's export codes. The two published vectors
//! come from dim13/otpauth (`migration/convert_test.go`, ISC license,
//! Copyright (c) 2020 Dimitri Sokolyuk); the other payloads are built here
//! field by field. Codes exported from the real app follow as fixtures.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use sailtoken_core::import::{
    read_migration_uri, ImportError, MigrationBatch, SkipReason, Skipped, MAX_BATCH_SIZE,
    MAX_MIGRATION_PAYLOAD,
};
use sailtoken_core::otp::{code_at, Algorithm, TotpSettings};

// "Hello!\xde\xad\xbe\xef", the Key Uri Format's example secret.
const SECRET: &[u8] = b"Hello!\xde\xad\xbe\xef";
const SECRET_BASE32: &str = "JBSWY3DPEHPK3PXP";

const SHA1: u64 = 1;
const SHA256: u64 = 2;
const SHA512: u64 = 3;
const MD5: u64 = 4;
const SIX: u64 = 1;
const EIGHT: u64 = 2;
const HOTP: u64 = 1;
const TOTP: u64 = 2;

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn number(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(field << 3, &mut out);
    varint(value, &mut out);
    out
}

fn bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(field << 3 | 2, &mut out);
    varint(value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

struct Account<'a> {
    secret: &'a [u8],
    name: &'a str,
    issuer: &'a str,
    algorithm: u64,
    digits: u64,
    kind: u64,
}

const ALICE: Account = Account {
    secret: SECRET,
    name: "alice@example.com",
    issuer: "Example",
    algorithm: SHA1,
    digits: SIX,
    kind: TOTP,
};

fn parameters(account: &Account) -> Vec<u8> {
    [
        bytes(1, account.secret),
        bytes(2, account.name.as_bytes()),
        bytes(3, account.issuer.as_bytes()),
        number(4, account.algorithm),
        number(5, account.digits),
        number(6, account.kind),
    ]
    .concat()
}

fn payload(accounts: &[Account], batch: Option<(u64, u64, u64)>) -> Vec<u8> {
    let mut out: Vec<u8> = accounts
        .iter()
        .flat_map(|account| bytes(1, &parameters(account)))
        .collect();
    out.extend(number(2, 1));
    if let Some((size, index, id)) = batch {
        out.extend([number(3, size), number(4, index), number(5, id)].concat());
    }
    out
}

/// As Google writes it: standard Base64 with padding, percent-encoded.
fn uri(payload: &[u8]) -> String {
    let data = STANDARD
        .encode(payload)
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    format!("otpauth-migration://offline?data={data}")
}

fn read_all(payload: &[u8]) -> sailtoken_core::import::Import {
    MigrationBatch::new(read_migration_uri(&uri(payload)).unwrap())
        .finish()
        .unwrap()
}

fn same_codes(settings: &TotpSettings, base32: &str, algorithm: Algorithm, digits: u8) {
    let expected = TotpSettings::new(
        base32,
        algorithm,
        digits,
        30,
        sailtoken_core::otp::Encoder::Decimal,
    )
    .unwrap();
    for time in [59, 1_111_111_109, 2_000_000_000] {
        assert_eq!(
            code_at(settings, time).to_string(),
            code_at(&expected, time).to_string()
        );
    }
}

#[test]
fn reads_the_published_vector() {
    let code = read_migration_uri(
        "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC",
    )
    .unwrap();
    assert_eq!((code.batch_index(), code.batch_size()), (0, 1));
    let import = MigrationBatch::new(code).finish().unwrap();

    assert!(import.skipped.is_empty());
    let account = &import.accounts[0];
    assert_eq!(account.issuer, "Example");
    assert_eq!(account.account, "alice@google.com");
    assert_eq!(account.settings.period(), 30);
    same_codes(&account.settings, SECRET_BASE32, Algorithm::Sha1, 6);
}

#[test]
fn reads_the_published_vector_with_padding() {
    let import = MigrationBatch::new(
        read_migration_uri(
            "otpauth-migration://offline?data=CjsKFBHMQnKu/odWlB/zUy+dfiRIaHj0EhhFeGFtcGxlOmFsaWNlQGdvb2dsZS5jb20aB0V4YW1wbGUwAg==",
        )
        .unwrap(),
    )
    .finish()
    .unwrap();

    assert_eq!(import.accounts.len(), 1);
    assert_eq!(import.accounts[0].account, "alice@google.com");
}

#[test]
fn maps_algorithms_and_lengths() {
    let rfc_secret = b"12345678901234567890123456789012";
    let import = read_all(&payload(
        &[
            Account {
                secret: rfc_secret,
                algorithm: SHA256,
                digits: EIGHT,
                ..ALICE
            },
            Account {
                algorithm: SHA512,
                digits: SIX,
                ..ALICE
            },
            Account {
                algorithm: 0,
                digits: 0,
                kind: 0,
                ..ALICE
            },
        ],
        None,
    ));

    assert!(import.skipped.is_empty());
    let [sha256, sha512, unspecified] = &import.accounts[..] else {
        panic!("three accounts expected");
    };
    same_codes(
        &sha256.settings,
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====",
        Algorithm::Sha256,
        8,
    );
    same_codes(&sha512.settings, SECRET_BASE32, Algorithm::Sha512, 6);
    same_codes(&unspecified.settings, SECRET_BASE32, Algorithm::Sha1, 6);
}

#[test]
fn splits_the_issuer_from_the_name() {
    let import = read_all(&payload(
        &[
            Account {
                name: "Label:bob",
                issuer: "",
                ..ALICE
            },
            Account {
                name: "Example: carol",
                ..ALICE
            },
            Account {
                name: "Other:dave",
                ..ALICE
            },
            Account {
                name: "erin",
                issuer: "",
                ..ALICE
            },
        ],
        None,
    ));

    let names: Vec<_> = import
        .accounts
        .iter()
        .map(|account| (account.issuer.as_str(), account.account.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("Label", "bob"),
            ("Example", "carol"),
            ("Example", "Other:dave"),
            ("", "erin"),
        ]
    );
}

#[test]
fn skips_accounts_sailtoken_cannot_use_by_position() {
    let import = read_all(&payload(
        &[
            ALICE,
            Account {
                kind: HOTP,
                ..ALICE
            },
            Account {
                algorithm: MD5,
                ..ALICE
            },
            Account { kind: 7, ..ALICE },
            Account { digits: 3, ..ALICE },
            Account {
                secret: b"",
                ..ALICE
            },
            Account {
                secret: &[0; 513],
                ..ALICE
            },
            ALICE,
        ],
        None,
    ));

    assert_eq!(import.accounts.len(), 2);
    let skipped = |position, reason| Skipped { position, reason };
    assert_eq!(
        import.skipped,
        [
            skipped(2, SkipReason::Hotp),
            skipped(3, SkipReason::Unsupported),
            skipped(4, SkipReason::Unsupported),
            skipped(5, SkipReason::Unsupported),
            skipped(6, SkipReason::Invalid),
            skipped(7, SkipReason::Invalid),
        ]
    );
}

#[test]
fn skips_names_that_are_not_utf8() {
    let mut broken = parameters(&ALICE);
    broken.extend(bytes(2, b"\xff"));
    let import = read_all(&[bytes(1, &broken), bytes(1, &parameters(&ALICE))].concat());

    assert_eq!(
        import.skipped,
        [Skipped {
            position: 1,
            reason: SkipReason::Invalid
        }]
    );
    assert_eq!(import.accounts.len(), 1);
}

#[test]
fn ignores_unknown_fields() {
    let mut parameters = parameters(&ALICE);
    parameters.extend([number(7, 4), bytes(8, b"id"), number(20, 1)].concat());
    let import = read_all(&[bytes(1, &parameters), bytes(15, b"later"), number(2, 1)].concat());

    assert_eq!(import.accounts.len(), 1);
}

#[test]
fn collects_the_codes_of_a_batch_in_any_order() {
    let bob = Account {
        name: "bob",
        ..ALICE
    };
    let first = uri(&payload(&[ALICE], Some((3, 0, 77))));
    let second = uri(&payload(
        &[
            Account {
                kind: HOTP,
                ..ALICE
            },
            bob,
        ],
        Some((3, 1, 77)),
    ));
    let third = uri(&payload(&[ALICE], Some((3, 2, 77))));

    let mut batch = MigrationBatch::new(read_migration_uri(&third).unwrap());
    assert_eq!((batch.scanned(), batch.size()), (1, 3));
    assert!(batch.add(read_migration_uri(&first).unwrap()).unwrap());
    assert!(!batch.add(read_migration_uri(&third).unwrap()).unwrap());
    let mut batch = batch.finish().unwrap_err();
    assert_eq!(batch.scanned(), 2);

    assert!(batch.add(read_migration_uri(&second).unwrap()).unwrap());
    assert!(batch.is_complete());
    let import = batch.finish().unwrap();
    assert_eq!(import.accounts.len(), 3);
    assert_eq!(import.accounts[1].account, "bob");
    assert_eq!(
        import.skipped,
        [Skipped {
            position: 2,
            reason: SkipReason::Hotp
        }]
    );
}

#[test]
fn refuses_a_code_of_another_batch() {
    let mut batch =
        MigrationBatch::new(read_migration_uri(&uri(&payload(&[ALICE], Some((2, 0, 1))))).unwrap());

    for other in [
        payload(&[ALICE], Some((2, 1, 2))),
        payload(&[ALICE], Some((3, 1, 1))),
        payload(&[ALICE], None),
    ] {
        assert_eq!(
            batch.add(read_migration_uri(&uri(&other)).unwrap()),
            Err(ImportError::OtherBatch)
        );
    }
}

#[test]
fn reads_a_negative_batch_id() {
    let code = |index| uri(&payload(&[ALICE], Some((2, index, (-5_i64) as u64))));
    let mut batch = MigrationBatch::new(read_migration_uri(&code(0)).unwrap());

    assert_eq!(batch.add(read_migration_uri(&code(1)).unwrap()), Ok(true));
}

#[test]
fn tells_other_codes_apart() {
    for text in [
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
        "https://example.com",
        "",
        "otpauth-migration",
    ] {
        assert_eq!(
            read_migration_uri(text).unwrap_err(),
            ImportError::NotAnExport,
            "{text}"
        );
    }
    let upper = uri(&payload(&[ALICE], None)).replacen("otpauth-migration", "OTPAUTH-MIGRATION", 1);
    assert!(read_migration_uri(&upper).is_ok());
}

#[test]
fn refuses_malformed_codes() {
    let valid = payload(&[ALICE], None);
    for text in [
        "otpauth-migration://offline".to_owned(),
        "otpauth-migration://offline?other=1".to_owned(),
        "otpauth-migration://offline?data=not*base64".to_owned(),
        uri(&valid[..valid.len() - 3]),
        uri(&payload(&[ALICE], Some((2, 2, 1)))),
        uri(&[bytes(1, &parameters(&ALICE)), bytes(3, b"x")].concat()),
        uri(&bytes(1, &[number(1, 5), parameters(&ALICE)].concat())),
    ] {
        assert_eq!(
            read_migration_uri(&text).unwrap_err(),
            ImportError::Malformed,
            "{text}"
        );
    }
}

#[test]
fn refuses_codes_above_the_limits() {
    let big_batch = payload(&[ALICE], Some((MAX_BATCH_SIZE as u64 + 1, 0, 1)));
    let many: Vec<Account> = (0..101).map(|_| ALICE).collect();
    let long = bytes(15, &vec![0; MAX_MIGRATION_PAYLOAD]);

    for payload in [big_batch, payload(&many, None), long] {
        assert_eq!(
            read_migration_uri(&uri(&payload)).unwrap_err(),
            ImportError::TooLarge
        );
    }
}
