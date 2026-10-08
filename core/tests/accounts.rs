//! The account model on the TOTP fixture (`tools/gen-totp-fixture.py`).

use sailfactor_core::accounts::{self, AccountError, AccountKind, UUID_LENGTH};
use sailfactor_core::kdbx::{CompositeKey, Database, KdbxError, NewField};
use sailfactor_core::otp::{code_at, Algorithm, Encoder, TotpSettings};

const FIXTURE: &[u8] = include_bytes!("fixtures/totp-entries.kdbx");
const NOW: i64 = 1_790_000_000;
const EXAMPLE_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn open() -> Database {
    Database::open(
        FIXTURE,
        CompositeKey::new(Some(b"sailvault-fixture"), None).unwrap(),
    )
    .unwrap()
}

fn uuid_of(database: &Database, issuer: &str) -> [u8; UUID_LENGTH] {
    accounts::list(database)
        .unwrap()
        .into_iter()
        .find(|account| account.issuer.as_str() == issuer)
        .unwrap_or_else(|| panic!("{issuer} missing"))
        .uuid
}

fn example() -> TotpSettings {
    TotpSettings::new(EXAMPLE_SECRET, Algorithm::Sha1, 6, 30, Encoder::Decimal).unwrap()
}

#[test]
fn lists_every_entry_with_what_it_can_show() {
    let database = open();
    let accounts = accounts::list(&database).unwrap();
    assert_eq!(accounts.len(), 12);
    let first = &accounts[0];
    assert_eq!(
        (first.issuer.as_str(), first.name.as_str()),
        ("SHA-1 six digits", "alice@example.org")
    );
    assert_eq!(
        first.kind,
        AccountKind::Totp {
            digits: 6,
            period: 30,
            encoder: Encoder::Decimal
        }
    );
    let kind = |issuer: &str| {
        accounts
            .iter()
            .find(|account| account.issuer.as_str() == issuer)
            .unwrap()
            .kind
    };
    assert_eq!(kind("Counter based"), AccountKind::Hotp);
    assert_eq!(kind("No code"), AccountKind::NoCode);
    assert_eq!(
        kind("Steam"),
        AccountKind::Totp {
            digits: 5,
            period: 30,
            encoder: Encoder::Steam
        }
    );
    let codes = accounts
        .iter()
        .filter(|account| matches!(account.kind, AccountKind::Totp { .. }))
        .count();
    assert_eq!(codes, 10);
}

#[test]
fn computes_the_code_and_the_seconds_left() {
    let database = open();
    let uuid = uuid_of(&database, "SHA-1 six digits");
    let (code, remaining) = accounts::code(&database, &uuid, 1_111_111_109).unwrap();
    assert_eq!(code, code_at(&example(), 1_111_111_109));
    assert_eq!(remaining, 1);

    let no_code = uuid_of(&database, "No code");
    assert_eq!(
        accounts::code(&database, &no_code, 0).map(|_| ()),
        Err(AccountError::NoCode)
    );
    assert_eq!(
        accounts::code(&database, &[0xee; UUID_LENGTH], 0).map(|_| ()),
        Err(AccountError::Kdbx(KdbxError::UnknownEntry))
    );
}

#[test]
fn an_added_account_survives_a_save_with_its_secret_protected() {
    let mut database = open();
    let uuid = accounts::add(&mut database, "Example", "new@example.org", &example(), NOW).unwrap();

    let reopened = Database::open(
        &database.save().unwrap(),
        CompositeKey::new(Some(b"sailvault-fixture"), None).unwrap(),
    )
    .unwrap();
    let entry = reopened.entry(&uuid).unwrap();
    let otp = entry.field("otp").unwrap();
    assert!(otp.is_protected());
    assert_eq!(
        otp.value().as_str(),
        "otpauth://totp/Example:new%40example.org?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Example"
    );
    assert!(!entry.field("Title").unwrap().is_protected());
    let (code, _) = accounts::code(&reopened, &uuid, 59).unwrap();
    assert_eq!(code, code_at(&example(), 59));
    assert_eq!(uuid_of(&reopened, "Example"), uuid);
}

#[test]
fn renaming_keeps_the_previous_names_in_the_history() {
    let mut database = open();
    let uuid = uuid_of(&database, "SHA-1 six digits");
    assert_eq!(
        accounts::rename(&mut database, &uuid, "Renamed", "alice", NOW),
        Ok(true)
    );
    assert_eq!(
        accounts::rename(&mut database, &uuid, "Renamed", "alice", NOW),
        Ok(false)
    );
    let entry = database.entry(&uuid).unwrap();
    assert_eq!(entry.history().count(), 1);
    assert_eq!(entry.field("UserName").unwrap().value().as_str(), "alice");
    assert!(entry
        .field("otp")
        .unwrap()
        .value()
        .contains("Example:alice%40example.org"));
}

#[test]
fn deleting_moves_to_the_recycle_bin_first() {
    let mut database = open();
    let uuid = uuid_of(&database, "Steam");
    assert_eq!(accounts::deletes_permanently(&database, &uuid), Ok(false));
    assert_eq!(accounts::delete(&mut database, &uuid, NOW), Ok(false));
    assert_eq!(accounts::deletes_permanently(&database, &uuid), Ok(true));
    let listed = accounts::list(&database).unwrap();
    assert_eq!(listed.len(), 11);
    assert!(listed.iter().all(|account| account.uuid != uuid));
    assert!(database.in_recycle_bin(&uuid).unwrap());

    assert_eq!(accounts::delete(&mut database, &uuid, NOW), Ok(true));
    assert!(database.entry(&uuid).is_none());
}

#[test]
fn unreadable_settings_are_listed_as_such() {
    let mut database = open();
    let root = database.root_group().unwrap().uuid().unwrap();
    database
        .add_entry(
            &root,
            &[("Title", "Broken"), ("otp", "otpauth://totp/x?secret=A")],
            NOW,
        )
        .unwrap();
    let broken = accounts::list(&database)
        .unwrap()
        .into_iter()
        .find(|account| account.issuer.as_str() == "Broken")
        .unwrap();
    assert_eq!(broken.kind, AccountKind::Unreadable);
}

#[test]
fn entries_with_a_password_are_marked() {
    let mut database = open();
    assert!(
        accounts::list(&database)
            .unwrap()
            .iter()
            .all(|account| !account.has_password),
        "the TOTP fixture stores no passwords"
    );
    let root = database.root_group().unwrap().uuid().unwrap();
    let login = database
        .add_entry_with_fields(
            &root,
            vec![
                NewField::new("Title", "Mail", false),
                NewField::new("Password", "made-up password", false),
            ],
            NOW,
        )
        .unwrap();
    let both = database
        .add_entry_with_fields(
            &root,
            vec![
                NewField::new("Title", "Forum", false),
                NewField::new("Password", "another made-up password", false),
                NewField::new(
                    "otp",
                    &format!("otpauth://totp/Forum:me?secret={EXAMPLE_SECRET}"),
                    true,
                ),
            ],
            NOW,
        )
        .unwrap();
    let listed = accounts::list(&database).unwrap();
    let find = |uuid| listed.iter().find(|account| account.uuid == uuid).unwrap();
    assert!(find(login).has_password);
    assert_eq!(find(login).kind, AccountKind::NoCode);
    assert!(find(both).has_password);
    assert!(matches!(find(both).kind, AccountKind::Totp { .. }));
}
