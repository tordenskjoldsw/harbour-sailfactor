//! Codes for the entries of `fixtures/totp-entries.kdbx`
//! (`tools/gen-totp-fixture.py`) against `keepassxc-cli show -t`, and
//! accounts written by SailFactor read back by KeePassXC.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sailfactor_core::kdbx::{CompositeKey, Database, Entry};
use sailfactor_core::otp::{
    code_at, settings_from_attributes, write_uri, Algorithm, Encoder, OtpError, TotpSettings,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/totp-entries.kdbx");
const PASSWORD: &str = "sailvault-fixture";
const NOW: i64 = 1_790_000_000;

fn key() -> CompositeKey {
    CompositeKey::new(Some(PASSWORD.as_bytes()), None).unwrap()
}

fn title(entry: &Entry<'_>) -> String {
    entry
        .field("Title")
        .map(|field| field.value().to_string())
        .unwrap_or_default()
}

fn settings(entry: &Entry<'_>) -> Result<Option<TotpSettings>, OtpError> {
    let fields: HashMap<String, String> = entry
        .fields()
        .map(|field| (field.key().to_string(), field.value().to_string()))
        .collect();
    settings_from_attributes(|name| fields.get(name).map(String::as_str))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct TempFile(PathBuf);

impl TempFile {
    fn write(name: &str, data: &[u8]) -> Self {
        let path =
            std::env::temp_dir().join(format!("sailfactor-{}-{name}.kdbx", std::process::id()));
        std::fs::write(&path, data).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn keepassxc_totp(file: &TempFile, title: &str) -> String {
    let mut child = Command::new("keepassxc-cli")
        .args(["show", "-q", "-t"])
        .arg(&file.0)
        .arg(title)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be installed");
    writeln!(child.stdin.take().unwrap(), "{PASSWORD}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{title}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// The code keepassxc-cli shows matches ours at the time before or after
/// the call, which covers a step boundary falling in between.
fn assert_same_code(file: &TempFile, title: &str, settings: &TotpSettings) {
    let before = unix_now();
    let shown = keepassxc_totp(file, title);
    let after = unix_now();
    let ours = [code_at(settings, before), code_at(settings, after)];
    assert!(
        ours.iter().any(|code| code.as_str() == shown),
        "{title}: keepassxc-cli shows {shown}, SailFactor {:?}",
        ours.iter().map(|code| code.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn every_entry_shows_the_code_keepassxc_shows() {
    let database = Database::open(FIXTURE, key()).unwrap();
    let file = TempFile::write("totp-entries", FIXTURE);
    let mut compared = Vec::new();
    for entry in database.root_group().unwrap().entries() {
        let title = title(&entry);
        match (title.as_str(), settings(&entry)) {
            ("Counter based", result) => assert_eq!(result, Err(OtpError::Hotp)),
            ("No code", result) => assert_eq!(result, Ok(None)),
            (_, Ok(Some(settings))) => {
                assert_same_code(&file, &title, &settings);
                compared.push(title);
            }
            (_, other) => panic!("{title}: {other:?}"),
        }
    }
    assert_eq!(compared.len(), 10, "{compared:?}");
}

#[test]
fn the_fixture_entries_have_the_expected_settings() {
    let database = Database::open(FIXTURE, key()).unwrap();
    let by_title: HashMap<String, TotpSettings> = database
        .root_group()
        .unwrap()
        .entries()
        .filter_map(|entry| Some((title(&entry), settings(&entry).ok()??)))
        .collect();
    let summary = |name: &str| {
        let settings = &by_title[name];
        (
            settings.algorithm,
            settings.digits,
            settings.period,
            settings.encoder,
        )
    };
    assert_eq!(
        summary("SHA-256 eight digits"),
        (Algorithm::Sha256, 8, 30, Encoder::Decimal)
    );
    assert_eq!(
        summary("SHA-512 sixty seconds"),
        (Algorithm::Sha512, 6, 60, Encoder::Decimal)
    );
    assert_eq!(summary("Steam"), (Algorithm::Sha1, 5, 30, Encoder::Steam));
    assert_eq!(
        summary("Legacy settings"),
        (Algorithm::Sha1, 8, 45, Encoder::Decimal)
    );
    assert_eq!(
        summary("Legacy Steam"),
        (Algorithm::Sha1, 5, 30, Encoder::Steam)
    );
    assert_eq!(
        summary("KeeOtp"),
        (Algorithm::Sha256, 7, 40, Encoder::Decimal)
    );
    assert_eq!(
        summary("KeePass 2"),
        (Algorithm::Sha512, 8, 20, Encoder::Decimal)
    );
}

#[test]
fn accounts_written_by_sailfactor_show_the_same_code_in_keepassxc() {
    let mut database = Database::open(FIXTURE, key()).unwrap();
    let root = database.root_group().unwrap().uuid().unwrap();
    let accounts = [
        (
            "Written SHA-1",
            "user one",
            "JBSWY3DPEHPK3PXP",
            Algorithm::Sha1,
            6,
            30,
            Encoder::Decimal,
        ),
        (
            "Written: SHA-256",
            "two@example.org",
            "NBSWY3DPEE",
            Algorithm::Sha256,
            8,
            60,
            Encoder::Decimal,
        ),
        (
            "Written Steam",
            "",
            "GEZDGNBVGY3TQOJQ",
            Algorithm::Sha1,
            5,
            30,
            Encoder::Steam,
        ),
    ];
    let mut written = Vec::new();
    for (title, user_name, secret, algorithm, digits, period, encoder) in accounts {
        let settings = TotpSettings::new(secret, algorithm, digits, period, encoder).unwrap();
        let uri = write_uri(title, user_name, &settings);
        database
            .add_entry(
                &root,
                &[("Title", title), ("UserName", user_name), ("otp", &uri)],
                NOW,
            )
            .unwrap();
        written.push((title, settings));
    }
    let saved = database.save().unwrap();
    let file = TempFile::write("written-accounts", &saved);
    let reopened = Database::open(&saved, key()).unwrap();
    for (title, settings) in written {
        let entry = reopened
            .root_group()
            .unwrap()
            .entries()
            .find(|entry| self::title(entry) == title)
            .unwrap();
        assert_eq!(
            self::settings(&entry),
            Ok(Some(settings.clone())),
            "{title}"
        );
        assert_same_code(&file, title, &settings);
    }
}
