//! The accounts of an authenticator file, on top of the KDBX model. An
//! account is an entry outside the recycle bin: its title names the issuer,
//! its user name the account, and its attributes hold the TOTP settings as
//! KeePassXC stores them. Entries without settings are listed too, so
//! nothing in a file shared with KeePassXC is hidden, except the entry that
//! holds the Nextcloud sync settings, which the settings page shows.

use zeroize::Zeroizing;

use crate::kdbx::{Database, Entry, KdbxError, NewField};
use crate::otp::{
    self, Encoder, OtpError, TotpSettings, ATTRIBUTE_KEEPASS2_ALGORITHM, ATTRIBUTE_KEEPASS2_LENGTH,
    ATTRIBUTE_KEEPASS2_PERIOD, ATTRIBUTE_KEEPASS2_SECRET, ATTRIBUTE_OTP, ATTRIBUTE_SEED,
    ATTRIBUTE_SETTINGS,
};

pub const UUID_LENGTH: usize = 16;

const TITLE: &str = "Title";
const USER_NAME: &str = "UserName";
const SETTINGS_ATTRIBUTES: [&str; 7] = [
    ATTRIBUTE_SETTINGS,
    ATTRIBUTE_SEED,
    ATTRIBUTE_OTP,
    ATTRIBUTE_KEEPASS2_SECRET,
    ATTRIBUTE_KEEPASS2_ALGORITHM,
    ATTRIBUTE_KEEPASS2_LENGTH,
    ATTRIBUTE_KEEPASS2_PERIOD,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    Totp {
        digits: u8,
        period: u32,
        encoder: Encoder,
    },
    /// A counter-based code, kept as it is but not computed.
    Hotp,
    /// Settings that cannot be read, such as a secret that is not Base32.
    Unreadable,
    /// An entry without TOTP settings, such as a password from KeePassXC.
    NoCode,
}

pub struct Account {
    pub uuid: [u8; UUID_LENGTH],
    pub issuer: Zeroizing<String>,
    pub name: Zeroizing<String>,
    pub kind: AccountKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    Kdbx(KdbxError),
    Otp(OtpError),
    NoCode,
}

impl From<KdbxError> for AccountError {
    fn from(error: KdbxError) -> Self {
        Self::Kdbx(error)
    }
}

impl From<OtpError> for AccountError {
    fn from(error: OtpError) -> Self {
        Self::Otp(error)
    }
}

/// The accounts in document order, without the recycle bin.
pub fn list(database: &Database) -> Result<Vec<Account>, KdbxError> {
    let mut accounts = Vec::new();
    let sync_entry = database.sync_entry();
    for listed in database.entries()? {
        let Some(uuid) = listed.entry.uuid() else {
            continue;
        };
        if Some(uuid) == sync_entry || database.in_recycle_bin(&uuid)? {
            continue;
        }
        let kind = match entry_settings(&listed.entry) {
            Ok(Some(settings)) => AccountKind::Totp {
                digits: settings.digits(),
                period: settings.period(),
                encoder: settings.encoder(),
            },
            Ok(None) => AccountKind::NoCode,
            Err(OtpError::Hotp) => AccountKind::Hotp,
            Err(_) => AccountKind::Unreadable,
        };
        accounts.push(Account {
            uuid,
            issuer: field(&listed.entry, TITLE),
            name: field(&listed.entry, USER_NAME),
            kind,
        });
    }
    Ok(accounts)
}

/// The code of the account with `uuid` at `unix_seconds` and the seconds
/// until it changes.
pub fn code(
    database: &Database,
    uuid: &[u8; UUID_LENGTH],
    unix_seconds: u64,
) -> Result<(Zeroizing<String>, u32), AccountError> {
    let entry = database.entry(uuid).ok_or(KdbxError::UnknownEntry)?;
    let settings = entry_settings(&entry)?.ok_or(AccountError::NoCode)?;
    Ok((
        otp::code_at(&settings, unix_seconds),
        otp::seconds_remaining(&settings, unix_seconds),
    ))
}

/// Adds an account to the root group, its `otp` attribute protected as
/// KeePassXC writes it, and returns its UUID.
pub fn add(
    database: &mut Database,
    issuer: &str,
    name: &str,
    settings: &TotpSettings,
    now: i64,
) -> Result<[u8; UUID_LENGTH], AccountError> {
    let root = database
        .root_group()?
        .uuid()
        .ok_or(KdbxError::UnknownGroup)?;
    let uri = otp::write_uri(issuer, name, settings);
    let fields = vec![
        NewField::new(TITLE, issuer, false),
        NewField::new(USER_NAME, name, false),
        NewField::new(ATTRIBUTE_OTP, &uri, true),
    ];
    Ok(database.add_entry_with_fields(&root, fields, now)?)
}

/// Renames an account; the previous state goes into the entry's history.
/// The `otp` attribute keeps its label, as in KeePassXC. Returns whether
/// anything changed.
pub fn rename(
    database: &mut Database,
    uuid: &[u8; UUID_LENGTH],
    issuer: &str,
    name: &str,
    now: i64,
) -> Result<bool, KdbxError> {
    database.update_entry(uuid, &[(TITLE, issuer), (USER_NAME, name)], now)
}

/// Whether `delete` would remove the account for good instead of moving it
/// to the recycle bin, which happens when the file has the bin turned off.
pub fn deletes_permanently(
    database: &Database,
    uuid: &[u8; UUID_LENGTH],
) -> Result<bool, KdbxError> {
    database.deletes_permanently(uuid)
}

/// Moves an account to the recycle bin, or removes it for good when it is
/// already there or the bin is off. Returns whether it was removed for
/// good.
pub fn delete(
    database: &mut Database,
    uuid: &[u8; UUID_LENGTH],
    now: i64,
) -> Result<bool, KdbxError> {
    database.delete_entry(uuid, now)
}

fn entry_settings(entry: &Entry<'_>) -> Result<Option<TotpSettings>, OtpError> {
    let values = SETTINGS_ATTRIBUTES.map(|name| entry.field(name).map(|field| field.value()));
    otp::settings_from_attributes(|name| {
        SETTINGS_ATTRIBUTES
            .iter()
            .position(|attribute| *attribute == name)
            .and_then(|index| values[index].as_ref())
            .map(|value| value.as_str())
    })
}

fn field(entry: &Entry<'_>, key: &str) -> Zeroizing<String> {
    entry
        .field(key)
        .map(|field| field.value())
        .unwrap_or_default()
}
