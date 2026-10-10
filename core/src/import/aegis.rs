//! Aegis vault files, plain and encrypted, as `docs/vault.md` of the Aegis
//! repository describes them (used as a description only; Aegis is
//! GPL-3.0). An encrypted vault wraps a random master key once per slot;
//! a password slot derives its wrapping key with scrypt, and AES-256-GCM
//! protects both the key and the content. Only password slots can be
//! opened here.
//!
//! serde_json parses the content into strings that are wiped when the
//! reader is done; its own scratch buffers and scrypt's working memory are
//! freed without wiping, which `docs/import-formats.md` records.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::{Import, ImportError, SkipReason, MAX_ENTRIES};
use crate::otp::{Algorithm, Encoder, ParsedUri, TotpSettings, DEFAULT_PERIOD, STEAM_DIGITS};

/// Icons travel inside the file as Base64 JPEG, so a vault can be large.
pub const MAX_AEGIS_LENGTH: usize = 16 << 20;
// scrypt needs 128 * r * n bytes: at most 256 MiB, the ceiling of the
// Argon2 levels. Aegis uses n = 2^15, r = 8, p = 1.
const MAX_LOG_N: u8 = 18;
const MAX_R: u32 = 8;
const MAX_P: u32 = 4;
const MAX_TEXT_LENGTH: usize = 1024;
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const PASSWORD_SLOT: u64 = 1;
const VAULT_VERSION: u64 = 1;
const CONTENT_VERSION: u64 = 3;

/// Whether the vault needs a password, without reading it further.
pub fn aegis_is_encrypted(bytes: &[u8]) -> Result<bool, ImportError> {
    let vault = parse(bytes)?;
    Ok(!vault.0["header"]["slots"].is_null())
}

/// Reads the accounts of a vault; `password` is needed for an encrypted
/// one. `PasswordRequired` without it, `WrongPassword` when no password
/// slot opens.
pub fn read_aegis(bytes: &[u8], password: Option<&[u8]>) -> Result<Import, ImportError> {
    let vault = parse(bytes)?;
    if vault.0["version"].as_u64() != Some(VAULT_VERSION) {
        return Err(ImportError::Malformed);
    }
    let header = &vault.0["header"];
    let content = if header["slots"].is_null() && header["params"].is_null() {
        // A plain vault keeps the content as an object, not as a string.
        if !vault.0["db"].is_object() {
            return Err(ImportError::Malformed);
        }
        Wiped(vault.0["db"].clone())
    } else {
        let password = password.ok_or(ImportError::PasswordRequired)?;
        let master_key = open_slots(header, password)?;
        let plaintext = decrypt_content(&vault.0, &master_key)?;
        Wiped(serde_json::from_slice(&plaintext).map_err(|_| ImportError::Malformed)?)
    };
    read_content(&content.0)
}

/// A parsed JSON value whose strings are wiped when it is dropped: the
/// file, which holds every secret of a plain vault, and the decrypted
/// content.
struct Wiped(Value);

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(fields) => fields.iter_mut().for_each(|(_, field)| wipe(field)),
        _ => {}
    }
}

fn parse(bytes: &[u8]) -> Result<Wiped, ImportError> {
    if bytes.len() > MAX_AEGIS_LENGTH {
        return Err(ImportError::TooLarge);
    }
    let vault = Wiped(serde_json::from_slice(bytes).map_err(|_| ImportError::NotAnExport)?);
    if !vault.0["header"].is_object() || vault.0.get("db").is_none() {
        return Err(ImportError::NotAnExport);
    }
    Ok(vault)
}

fn open_slots(header: &Value, password: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, ImportError> {
    let slots = header["slots"].as_array().ok_or(ImportError::Malformed)?;
    let mut any_password_slot = false;
    for slot in slots {
        if slot["type"].as_u64() != Some(PASSWORD_SLOT) {
            continue;
        }
        any_password_slot = true;
        let wrapping_key = derive_key(slot, password)?;
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        let wrapped = hex(&slot["key"], KEY_LENGTH)?;
        key.copy_from_slice(&wrapped);
        let params = &slot["key_params"];
        if decrypt(&wrapping_key, params, &mut key[..]).is_ok() {
            return Ok(key);
        }
    }
    Err(if any_password_slot {
        ImportError::WrongPassword
    } else {
        ImportError::Malformed
    })
}

fn derive_key(slot: &Value, password: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, ImportError> {
    let n = slot["n"].as_u64().ok_or(ImportError::Malformed)?;
    let r = slot["r"].as_u64().ok_or(ImportError::Malformed)?;
    let p = slot["p"].as_u64().ok_or(ImportError::Malformed)?;
    if !n.is_power_of_two() || n < 2 {
        return Err(ImportError::Malformed);
    }
    let log_n = n.trailing_zeros() as u8;
    let (r, p) = (
        u32::try_from(r).map_err(|_| ImportError::TooLarge)?,
        u32::try_from(p).map_err(|_| ImportError::TooLarge)?,
    );
    if log_n > MAX_LOG_N || r > MAX_R || p > MAX_P {
        return Err(ImportError::TooLarge);
    }
    let params =
        scrypt::Params::new(log_n, r, p, KEY_LENGTH).map_err(|_| ImportError::Malformed)?;
    let salt = hex(&slot["salt"], KEY_LENGTH)?;
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    scrypt::scrypt(password, &salt, &params, &mut key[..]).map_err(|_| ImportError::Malformed)?;
    Ok(key)
}

fn decrypt_content(
    vault: &Value,
    master_key: &[u8; KEY_LENGTH],
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let encoded = vault["db"].as_str().ok_or(ImportError::Malformed)?;
    let mut content = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| ImportError::Malformed)?,
    );
    // A content that fails its tag after the key opened is damaged, not a
    // wrong password.
    decrypt(master_key, &vault["header"]["params"], &mut content)
        .map_err(|_| ImportError::Malformed)?;
    Ok(content)
}

/// AES-256-GCM in place with the hex `nonce` and `tag` of `params`.
fn decrypt(key: &[u8; KEY_LENGTH], params: &Value, data: &mut [u8]) -> Result<(), ImportError> {
    let nonce = hex(&params["nonce"], NONCE_LENGTH)?;
    let tag = hex(&params["tag"], TAG_LENGTH)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ImportError::Malformed)?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", data, Tag::from_slice(&tag))
        .map_err(|_| ImportError::WrongPassword)
}

/// Exactly `length` bytes of lowercase or uppercase hex.
fn hex(value: &Value, length: usize) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let text = value.as_str().ok_or(ImportError::Malformed)?.as_bytes();
    if text.len() != 2 * length {
        return Err(ImportError::Malformed);
    }
    let digit = |symbol: u8| (symbol as char).to_digit(16).map(|digit| digit as u8);
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    for pair in text.chunks(2) {
        let (high, low) = digit(pair[0])
            .zip(digit(pair[1]))
            .ok_or(ImportError::Malformed)?;
        bytes.push(high << 4 | low);
    }
    Ok(bytes)
}

fn read_content(content: &Value) -> Result<Import, ImportError> {
    if content["version"].as_u64() != Some(CONTENT_VERSION) {
        return Err(ImportError::Malformed);
    }
    let entries = content["entries"]
        .as_array()
        .ok_or(ImportError::Malformed)?;
    if entries.len() > MAX_ENTRIES {
        return Err(ImportError::TooLarge);
    }
    let mut import = Import::default();
    for entry in entries {
        import.push(account(entry));
    }
    Ok(import)
}

fn account(entry: &Value) -> Result<ParsedUri, SkipReason> {
    let info = &entry["info"];
    let encoder = match entry["type"].as_str() {
        Some("totp") => Encoder::Decimal,
        Some("steam") => Encoder::Steam,
        Some("hotp") => return Err(SkipReason::Hotp),
        Some(_) => return Err(SkipReason::Unsupported),
        None => return Err(SkipReason::Invalid),
    };
    let algorithm = match info["algo"]
        .as_str()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("SHA1") => Algorithm::Sha1,
        Some("SHA256") => Algorithm::Sha256,
        Some("SHA512") => Algorithm::Sha512,
        Some(_) => return Err(SkipReason::Unsupported),
        None => return Err(SkipReason::Invalid),
    };
    let digits = match encoder {
        Encoder::Steam => STEAM_DIGITS,
        Encoder::Decimal => number(&info["digits"])?,
    };
    let period = match info["period"] {
        Value::Null => DEFAULT_PERIOD,
        ref period => number(period)?,
    };
    let secret = info["secret"].as_str().ok_or(SkipReason::Invalid)?;
    let settings = TotpSettings::new(secret, algorithm, digits, period, encoder)?;
    Ok(ParsedUri {
        issuer: text(&entry["issuer"])?,
        account: text(&entry["name"])?,
        settings,
    })
}

fn number<T: TryFrom<u64>>(value: &Value) -> Result<T, SkipReason> {
    value
        .as_u64()
        .and_then(|number| T::try_from(number).ok())
        .ok_or(SkipReason::Invalid)
}

/// A missing text is empty; anything else must be a string of bounded
/// length.
fn text(value: &Value) -> Result<String, SkipReason> {
    match value {
        Value::Null => Ok(String::new()),
        Value::String(text) if text.len() <= MAX_TEXT_LENGTH => Ok(text.clone()),
        _ => Err(SkipReason::Invalid),
    }
}
