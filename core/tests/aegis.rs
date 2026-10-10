//! Reading Aegis vault files. The vaults here are built field by field
//! after `docs/vault.md` of the Aegis repository, encrypted with the same
//! crates the reader uses; exports made in the Aegis app follow as
//! fixtures and check the reading against the real thing.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use sailtoken_core::import::{
    aegis_is_encrypted, read_aegis, ImportError, SkipReason, Skipped, MAX_AEGIS_LENGTH, MAX_ENTRIES,
};
use sailtoken_core::otp::{code_at, Algorithm, Encoder, TotpSettings};

const PASSWORD: &[u8] = b"made-up vault password";
const MASTER_KEY: [u8; 32] = [7; 32];
const SALT: [u8; 32] = [3; 32];
const SLOT_NONCE: [u8; 12] = [1; 12];
const CONTENT_NONCE: [u8; 12] = [2; 12];
// Small, so the tests stay fast; Aegis itself uses 2^15.
const TEST_N: u64 = 1 << 10;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn totp(issuer: &str, name: &str, secret: &str, algo: &str, digits: u64, period: u64) -> Value {
    json!({
        "type": "totp",
        "uuid": "01234567-89ab-4def-8123-456789abcdef",
        "name": name,
        "issuer": issuer,
        "note": "",
        "favorite": false,
        "icon": null,
        "info": { "secret": secret, "algo": algo, "digits": digits, "period": period },
        "groups": []
    })
}

fn content(entries: Vec<Value>) -> Value {
    json!({ "version": 3, "entries": entries, "groups": [] })
}

fn plain(entries: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": 1,
        "header": { "slots": null, "params": null },
        "db": content(entries)
    }))
    .unwrap()
}

/// AES-256-GCM, returning the ciphertext and the hex tag.
fn seal(key: &[u8], nonce: &[u8; 12], data: &[u8]) -> (Vec<u8>, String) {
    let mut buffer = data.to_vec();
    let tag = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut buffer)
        .unwrap();
    (buffer, hex(&tag))
}

fn slot(n: u64, password: &[u8]) -> Value {
    let params = scrypt::Params::new(n.trailing_zeros() as u8, 8, 1, 32).unwrap();
    let mut wrapping_key = [0u8; 32];
    scrypt::scrypt(password, &SALT, &params, &mut wrapping_key).unwrap();
    let (key, tag) = seal(&wrapping_key, &SLOT_NONCE, &MASTER_KEY);
    json!({
        "type": 1,
        "uuid": "11111111-2222-4333-8444-555555555555",
        "key": hex(&key),
        "key_params": { "nonce": hex(&SLOT_NONCE), "tag": tag },
        "n": n, "r": 8, "p": 1,
        "salt": hex(&SALT),
        "repaired": true,
        "is_backup": false
    })
}

fn encrypted_with(slots: Vec<Value>, entries: Vec<Value>) -> Value {
    let plaintext = serde_json::to_vec(&content(entries)).unwrap();
    let (db, tag) = seal(&MASTER_KEY, &CONTENT_NONCE, &plaintext);
    json!({
        "version": 1,
        "header": {
            "slots": slots,
            "params": { "nonce": hex(&CONTENT_NONCE), "tag": tag }
        },
        "db": STANDARD.encode(db)
    })
}

fn encrypted(entries: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&encrypted_with(vec![slot(TEST_N, PASSWORD)], entries)).unwrap()
}

fn alice() -> Value {
    totp(
        "Example",
        "alice@example.org",
        "JBSWY3DPEHPK3PXP",
        "SHA1",
        6,
        30,
    )
}

fn same_codes(settings: &TotpSettings, expected: TotpSettings) {
    for time in [59, 1_111_111_109, 2_000_000_000] {
        assert_eq!(
            code_at(settings, time).to_string(),
            code_at(&expected, time).to_string()
        );
    }
}

#[test]
fn reads_a_plain_vault() {
    let vault = plain(vec![
        alice(),
        totp(
            "Other",
            "bob",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            "SHA256",
            8,
            60,
        ),
    ]);

    assert!(!aegis_is_encrypted(&vault).unwrap());
    let import = read_aegis(&vault, None).unwrap();
    assert!(import.skipped.is_empty());
    let [alice, bob] = &import.accounts[..] else {
        panic!("two accounts expected");
    };
    assert_eq!(
        (alice.issuer.as_str(), alice.account.as_str()),
        ("Example", "alice@example.org")
    );
    same_codes(
        &alice.settings,
        TotpSettings::new("JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30, Encoder::Decimal).unwrap(),
    );
    // Unlike Google's export, Aegis keeps the time step.
    assert_eq!((bob.settings.digits(), bob.settings.period()), (8, 60));
    assert_eq!(bob.settings.algorithm(), Algorithm::Sha256);
}

#[test]
fn reads_steam_and_skips_what_sailtoken_cannot_use() {
    let mut steam = alice();
    steam["type"] = json!("steam");
    steam["info"]["digits"] = json!(5);
    let mut hotp = alice();
    hotp["type"] = json!("hotp");
    hotp["info"] =
        json!({ "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "counter": 3 });
    let mut motp = alice();
    motp["type"] = json!("motp");
    let mut md5 = alice();
    md5["info"]["algo"] = json!("MD5");
    let mut broken = alice();
    broken["info"]["secret"] = json!("not base32!");
    let mut untyped = alice();
    untyped.as_object_mut().unwrap().remove("type");

    let import = read_aegis(
        &plain(vec![steam, hotp, motp, md5, broken, untyped, alice()]),
        None,
    )
    .unwrap();

    assert_eq!(import.accounts.len(), 2);
    assert_eq!(import.accounts[0].settings.encoder(), Encoder::Steam);
    let skipped = |position, reason| Skipped { position, reason };
    assert_eq!(
        import.skipped,
        [
            skipped(2, SkipReason::Hotp),
            skipped(3, SkipReason::Unsupported),
            skipped(4, SkipReason::Unsupported),
            skipped(5, SkipReason::Invalid),
            skipped(6, SkipReason::Invalid),
        ]
    );
}

#[test]
fn opens_an_encrypted_vault_with_its_password() {
    let vault = encrypted(vec![alice()]);

    assert!(aegis_is_encrypted(&vault).unwrap());
    assert_eq!(
        read_aegis(&vault, None).unwrap_err(),
        ImportError::PasswordRequired
    );
    assert_eq!(
        read_aegis(&vault, Some(b"wrong password")).unwrap_err(),
        ImportError::WrongPassword
    );
    let import = read_aegis(&vault, Some(PASSWORD)).unwrap();
    assert_eq!(import.accounts[0].account, "alice@example.org");
}

#[test]
fn tries_every_password_slot_and_skips_other_slots() {
    let mut biometric = slot(TEST_N, b"key store");
    biometric["type"] = json!(2);
    let vault = encrypted_with(
        vec![
            biometric,
            slot(TEST_N, b"old password"),
            slot(TEST_N, PASSWORD),
        ],
        vec![alice()],
    );

    let import = read_aegis(&serde_json::to_vec(&vault).unwrap(), Some(PASSWORD)).unwrap();
    assert_eq!(import.accounts.len(), 1);
}

#[test]
fn a_vault_without_password_slots_cannot_be_opened() {
    let mut raw = slot(TEST_N, PASSWORD);
    raw["type"] = json!(0);
    let vault = serde_json::to_vec(&encrypted_with(vec![raw], vec![alice()])).unwrap();

    assert_eq!(
        read_aegis(&vault, Some(PASSWORD)).unwrap_err(),
        ImportError::Malformed
    );
}

#[test]
fn a_damaged_content_is_not_a_wrong_password() {
    let mut vault = encrypted_with(vec![slot(TEST_N, PASSWORD)], vec![alice()]);
    let mut db = STANDARD.decode(vault["db"].as_str().unwrap()).unwrap();
    db[0] ^= 1;
    vault["db"] = json!(STANDARD.encode(db));

    assert_eq!(
        read_aegis(&serde_json::to_vec(&vault).unwrap(), Some(PASSWORD)).unwrap_err(),
        ImportError::Malformed
    );
}

#[test]
fn refuses_key_derivation_beyond_the_limits() {
    for (n, r, p) in [(1u64 << 19, 8, 1), (TEST_N, 9, 1), (TEST_N, 8, 5)] {
        let mut slot = slot(TEST_N, PASSWORD);
        slot["n"] = json!(n);
        slot["r"] = json!(r);
        slot["p"] = json!(p);
        let vault = serde_json::to_vec(&encrypted_with(vec![slot], vec![alice()])).unwrap();
        assert_eq!(
            read_aegis(&vault, Some(PASSWORD)).unwrap_err(),
            ImportError::TooLarge,
            "n {n}, r {r}, p {p}"
        );
    }
    let mut odd = slot(TEST_N, PASSWORD);
    odd["n"] = json!(1000);
    let vault = serde_json::to_vec(&encrypted_with(vec![odd], vec![alice()])).unwrap();
    assert_eq!(
        read_aegis(&vault, Some(PASSWORD)).unwrap_err(),
        ImportError::Malformed
    );
}

#[test]
fn tells_other_files_apart() {
    for bytes in [
        &b"not json"[..],
        b"{\"version\": 1}",
        b"[1, 2]",
        b"{\"header\": {}, \"entries\": []}",
    ] {
        assert_eq!(
            read_aegis(bytes, None).unwrap_err(),
            ImportError::NotAnExport
        );
    }
}

#[test]
fn refuses_versions_it_does_not_know() {
    let mut vault: Value = serde_json::from_slice(&plain(vec![alice()])).unwrap();
    vault["db"]["version"] = json!(2);
    let older = serde_json::to_vec(&vault).unwrap();
    vault["db"]["version"] = json!(3);
    vault["version"] = json!(2);
    let newer = serde_json::to_vec(&vault).unwrap();

    for bytes in [older, newer] {
        assert_eq!(
            read_aegis(&bytes, None).unwrap_err(),
            ImportError::Malformed
        );
    }
}

#[test]
fn refuses_files_above_the_limits() {
    let entries = (0..=MAX_ENTRIES).map(|_| alice()).collect();
    assert_eq!(
        read_aegis(&plain(entries), None).unwrap_err(),
        ImportError::TooLarge
    );

    let huge = vec![b' '; MAX_AEGIS_LENGTH + 1];
    assert_eq!(read_aegis(&huge, None).unwrap_err(), ImportError::TooLarge);
}
