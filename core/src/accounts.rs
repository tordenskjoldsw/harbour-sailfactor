//! The accounts of an authenticator file, on top of the KDBX model. An
//! account is an entry outside the recycle bin: its title names the issuer,
//! its user name the account, and its attributes hold the TOTP settings as
//! KeePassXC stores them. Entries without settings are listed too, so
//! nothing in a file shared with KeePassXC is hidden, except the entry that
//! holds the Nextcloud sync settings, which the settings page shows.
//!
//! The order of the list is SailFactor's own: a list of entry UUIDs in the
//! database CustomData item `SailFactor/Order`. Moving an account rewrites
//! that item and leaves the entries where they are, so the order survives a
//! merge in which KeePassXC's rules move a changed entry to the end of its
//! group. Accounts the list does not name follow in document order.

use std::collections::{HashMap, HashSet};

use zeroize::Zeroizing;

use crate::kdbx::{Database, Element, Entry, Group, KdbxError, NewField, Node};
use crate::otp::{
    self, Encoder, OtpError, TotpSettings, ATTRIBUTE_KEEPASS2_ALGORITHM, ATTRIBUTE_KEEPASS2_LENGTH,
    ATTRIBUTE_KEEPASS2_PERIOD, ATTRIBUTE_KEEPASS2_SECRET, ATTRIBUTE_OTP, ATTRIBUTE_SEED,
    ATTRIBUTE_SETTINGS,
};

pub const UUID_LENGTH: usize = 16;

const TITLE: &str = "Title";
const USER_NAME: &str = "UserName";
const PASSWORD: &str = "Password";
const ORDER_KEY: &str = "SailFactor/Order";
// A crafted file cannot make listing expensive: UUIDs beyond this are
// ignored, far more accounts than anyone keeps.
const MAX_ORDERED: usize = 10_000;
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
    /// The entry stores a password, such as one from KeePassXC. SailFactor
    /// never writes or shows one; the pages warn about it.
    pub has_password: bool,
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
            has_password: !field(&listed.entry, PASSWORD).is_empty(),
        });
    }
    let position: HashMap<[u8; UUID_LENGTH], usize> = stored_order(database)
        .into_iter()
        .enumerate()
        .map(|(index, uuid)| (uuid, index))
        .collect();
    // Stable, so accounts the order does not name keep document order.
    accounts.sort_by_key(|account| position.get(&account.uuid).copied().unwrap_or(usize::MAX));
    Ok(accounts)
}

/// Moves the account with `uuid` in front of the account `before`, or to
/// the end without one, and stores the order of all accounts. Returns
/// whether the order changed.
pub fn move_account(
    database: &mut Database,
    uuid: &[u8; UUID_LENGTH],
    before: Option<&[u8; UUID_LENGTH]>,
) -> Result<bool, KdbxError> {
    let current: Vec<[u8; UUID_LENGTH]> = list(database)?
        .into_iter()
        .map(|account| account.uuid)
        .collect();
    if !current.contains(uuid) || before.is_some_and(|before| !current.contains(before)) {
        return Err(KdbxError::UnknownEntry);
    }
    if before == Some(uuid) {
        return Ok(false);
    }
    let mut order: Vec<[u8; UUID_LENGTH]> = current
        .iter()
        .copied()
        .filter(|other| other != uuid)
        .collect();
    let index = before
        .and_then(|before| order.iter().position(|other| other == before))
        .unwrap_or(order.len());
    order.insert(index, *uuid);
    if order == current {
        return Ok(false);
    }
    store_order(database, &order)?;
    Ok(true)
}

/// The UUIDs named by the order item, without malformed or repeated ones.
fn stored_order(database: &Database) -> Vec<[u8; UUID_LENGTH]> {
    let Some(value) = database
        .meta()
        .and_then(|meta| meta.child("CustomData"))
        .and_then(|data| {
            data.children_named("Item").find(|item| {
                item.child("Key")
                    .is_some_and(|key| *key.text() == *ORDER_KEY)
            })
        })
        .and_then(|item| item.child("Value"))
        .map(Element::text)
    else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    value
        .split_ascii_whitespace()
        .filter_map(decode_uuid)
        .filter(|uuid| seen.insert(*uuid))
        .take(MAX_ORDERED)
        .collect()
}

fn store_order(database: &mut Database, order: &[[u8; UUID_LENGTH]]) -> Result<(), KdbxError> {
    let value = order
        .iter()
        .map(|uuid| {
            uuid.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ");
    let meta = database
        .document_mut()
        .child_mut("Meta")
        .ok_or(KdbxError::InvalidXml("missing Meta"))?;
    if meta.child("CustomData").is_none() {
        meta.children.push(Node::Element(leaf("CustomData", None)));
    }
    let data = meta
        .child_mut("CustomData")
        .expect("CustomData was just ensured");
    let existing = data.children.iter_mut().find_map(|child| match child {
        Node::Element(item)
            if item.name == "Item"
                && item
                    .child("Key")
                    .is_some_and(|key| *key.text() == *ORDER_KEY) =>
        {
            Some(item)
        }
        _ => None,
    });
    match existing {
        Some(item) => match item.child_mut("Value") {
            Some(old) => *old = leaf("Value", Some(&value)),
            None => item
                .children
                .push(Node::Element(leaf("Value", Some(&value)))),
        },
        None => data.children.push(Node::Element(Element {
            name: "Item".to_owned(),
            attributes: Vec::new(),
            children: vec![
                Node::Element(leaf("Key", Some(ORDER_KEY))),
                Node::Element(leaf("Value", Some(&value))),
            ],
        })),
    }
    Ok(())
}

/// An element as the reader produces it: no text node when empty.
fn leaf(name: &str, text: Option<&str>) -> Element {
    Element {
        name: name.to_owned(),
        attributes: Vec::new(),
        children: text
            .filter(|text| !text.is_empty())
            .map(|text| Node::Text(Zeroizing::new(text.to_owned())))
            .into_iter()
            .collect(),
    }
}

fn decode_uuid(text: &str) -> Option<[u8; UUID_LENGTH]> {
    if text.len() != 2 * UUID_LENGTH || !text.is_ascii() {
        return None;
    }
    let mut uuid = [0u8; UUID_LENGTH];
    for (index, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).ok()?;
    }
    Some(uuid)
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

/// The entries and groups in the recycle bin, at any depth: deleted
/// accounts keep their secrets there until the bin is emptied.
pub fn recycle_bin_items(database: &Database) -> usize {
    fn items(group: &Group<'_>) -> usize {
        group.entries().count() + group.groups().map(|child| 1 + items(&child)).sum::<usize>()
    }
    database
        .existing_recycle_bin()
        .and_then(|bin| database.group(&bin))
        .map_or(0, |bin| items(&bin))
}

/// Removes everything in the recycle bin for good and records it as
/// deleted, so a merge or the sync removes it from other copies too.
/// Returns whether anything was removed.
pub fn empty_recycle_bin(database: &mut Database, now: i64) -> Result<bool, KdbxError> {
    database.empty_recycle_bin(now)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx::CompositeKey;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/totp-entries.kdbx");

    fn hex(uuid: &[u8; UUID_LENGTH]) -> String {
        uuid.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn malformed_and_repeated_uuids_in_the_order_are_ignored() {
        let mut database = Database::open(
            FIXTURE,
            CompositeKey::new(Some(b"sailvault-fixture"), None).unwrap(),
        )
        .unwrap();
        let listed = list(&database).unwrap();
        let last = listed.last().unwrap().uuid;
        let first = listed[0].uuid;
        // Store a valid order, then corrupt its value the way a crafted file
        // could; 0xee... is no entry of the fixture.
        assert!(move_account(&mut database, &last, Some(&first)).unwrap());
        let value = format!(
            "zz {} {} 0123 {} {}",
            hex(&last),
            hex(&last),
            "\u{e4}".repeat(16),
            hex(&[0xee; UUID_LENGTH])
        );
        let data = database
            .document_mut()
            .child_mut("Meta")
            .unwrap()
            .child_mut("CustomData")
            .unwrap();
        for child in &mut data.children {
            if let Node::Element(item) = child {
                if let Some(old) = item.child_mut("Value") {
                    *old = leaf("Value", Some(&value));
                }
            }
        }
        assert_eq!(stored_order(&database), vec![last, [0xee; UUID_LENGTH]]);
        let reordered = list(&database).unwrap();
        assert_eq!(reordered[0].uuid, last);
        assert_eq!(reordered.len(), listed.len());
        assert!(reordered[1..]
            .iter()
            .map(|account| account.uuid)
            .eq(listed[..listed.len() - 1]
                .iter()
                .map(|account| account.uuid)));
    }
}
