//! Google Authenticator's export codes,
//! `otpauth-migration://offline?data=<Base64 protobuf>`. The field numbers
//! follow `migration.proto` of dim13/otpauth (ISC license), a description
//! of the app's output; Google publishes none (`docs/import-formats.md`).
//! An export of many accounts spans several codes of one batch, which
//! `MigrationBatch` collects in any order.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use zeroize::Zeroizing;

use super::protobuf::{Malformed, Reader, Value};
use super::{Import, ImportError, SkipReason};
use crate::otp::{
    self, Algorithm, Encoder, ParsedUri, TotpSettings, DEFAULT_DIGITS, DEFAULT_PERIOD,
};

pub const MAX_BATCH_SIZE: usize = 50;
/// A QR code holds at most 2953 bytes, so its Base64 payload decodes to
/// less than this.
pub const MAX_MIGRATION_PAYLOAD: usize = 4096;
const MAX_ACCOUNTS_PER_CODE: usize = 100;
const MAX_TEXT_LENGTH: usize = 1024;
const SCHEME: &str = "otpauth-migration:";
const DATA_PARAMETER: &str = "data=";
const EIGHT_DIGITS: u8 = 8;

// Google writes standard Base64 with padding; other tools drop it.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

impl From<Malformed> for ImportError {
    fn from(_: Malformed) -> Self {
        Self::Malformed
    }
}

/// One scanned export code: its place in the batch and its entries.
#[derive(Debug)]
pub struct MigrationCode {
    batch_id: i32,
    batch_index: usize,
    batch_size: usize,
    entries: Vec<Result<ParsedUri, SkipReason>>,
}

impl MigrationCode {
    /// Counts from 0.
    pub fn batch_index(&self) -> usize {
        self.batch_index
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

/// Reads a scanned export code. `NotAnExport` for any other text, so the
/// scan page can try it as an ordinary account code.
pub fn read_migration_uri(uri: &str) -> Result<MigrationCode, ImportError> {
    let rest = uri
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .map(|_| &uri[SCHEME.len()..])
        .ok_or(ImportError::NotAnExport)?;
    let (_, query) = rest.split_once('?').ok_or(ImportError::Malformed)?;
    let data = query
        .split('&')
        .find_map(|item| item.strip_prefix(DATA_PARAMETER))
        .ok_or(ImportError::Malformed)?;
    if data.len() > MAX_MIGRATION_PAYLOAD * 2 {
        return Err(ImportError::TooLarge);
    }
    let data = otp::percent_decode(data);
    let payload = Zeroizing::new(BASE64.decode(&*data).map_err(|_| ImportError::Malformed)?);
    if payload.len() > MAX_MIGRATION_PAYLOAD {
        return Err(ImportError::TooLarge);
    }
    read_payload(&payload)
}

fn read_payload(payload: &[u8]) -> Result<MigrationCode, ImportError> {
    let mut code = MigrationCode {
        batch_id: 0,
        batch_index: 0,
        batch_size: 1,
        entries: Vec::new(),
    };
    let mut reader = Reader::new(payload);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Value::Bytes(parameters)) => {
                if code.entries.len() == MAX_ACCOUNTS_PER_CODE {
                    return Err(ImportError::TooLarge);
                }
                code.entries.push(read_parameters(parameters)?);
            }
            (2, Value::Varint(_)) => {}
            (3, Value::Varint(size)) => {
                code.batch_size = usize::try_from(size).map_err(|_| ImportError::TooLarge)?;
            }
            (4, Value::Varint(index)) => {
                code.batch_index = usize::try_from(index).map_err(|_| ImportError::Malformed)?;
            }
            // An int32 travels as a sign-extended 64-bit varint; the low
            // 32 bits are the value.
            (5, Value::Varint(id)) => code.batch_id = id as i32,
            (1..=5, _) => return Err(ImportError::Malformed),
            _ => {}
        }
    }
    // A single code may leave the batch fields out.
    code.batch_size = code.batch_size.max(1);
    if code.batch_size > MAX_BATCH_SIZE {
        return Err(ImportError::TooLarge);
    }
    if code.batch_index >= code.batch_size {
        return Err(ImportError::Malformed);
    }
    Ok(code)
}

/// One account. A broken message spoils the whole code; values SailToken
/// cannot use only skip the account.
fn read_parameters(bytes: &[u8]) -> Result<Result<ParsedUri, SkipReason>, ImportError> {
    let (mut secret, mut name, mut issuer): (&[u8], &[u8], &[u8]) = (&[], &[], &[]);
    let (mut algorithm, mut digits, mut kind) = (0, 0, 0);
    let mut reader = Reader::new(bytes);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Value::Bytes(value)) => secret = value,
            (2, Value::Bytes(value)) => name = value,
            (3, Value::Bytes(value)) => issuer = value,
            (4, Value::Varint(value)) => algorithm = value,
            (5, Value::Varint(value)) => digits = value,
            (6, Value::Varint(value)) => kind = value,
            // The HOTP counter and Google's own identifier.
            (7, Value::Varint(_)) | (8, Value::Bytes(_)) => {}
            (1..=8, _) => return Err(ImportError::Malformed),
            _ => {}
        }
    }
    Ok(account(secret, name, issuer, algorithm, digits, kind))
}

fn account(
    secret: &[u8],
    name: &[u8],
    issuer: &[u8],
    algorithm: u64,
    digits: u64,
    kind: u64,
) -> Result<ParsedUri, SkipReason> {
    // Unspecified values mean what Google Authenticator itself assumes.
    match kind {
        0 | 2 => {}
        1 => return Err(SkipReason::Hotp),
        _ => return Err(SkipReason::Unsupported),
    }
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Err(SkipReason::Unsupported),
    };
    let digits = match digits {
        0 | 1 => DEFAULT_DIGITS,
        2 => EIGHT_DIGITS,
        _ => return Err(SkipReason::Unsupported),
    };
    let (issuer, account) = names(name, issuer)?;
    let settings = TotpSettings::from_secret(
        Zeroizing::new(secret.to_vec()),
        algorithm,
        digits,
        DEFAULT_PERIOD,
        Encoder::Decimal,
    )?;
    Ok(ParsedUri {
        issuer,
        account,
        settings,
    })
}

/// The name often repeats the issuer as `Issuer:account`, as the label of
/// the URI the account came from; the prefix is dropped then, and taken as
/// the issuer when the issuer field is empty.
fn names(name: &[u8], issuer: &[u8]) -> Result<(String, String), SkipReason> {
    let (name, issuer) = (text(name)?, text(issuer)?);
    let (label_issuer, account) = match name.split_once(':') {
        Some((prefix, account)) if issuer.is_empty() || prefix == issuer => {
            (prefix, account.trim_start())
        }
        _ => ("", name),
    };
    let issuer = if issuer.is_empty() {
        label_issuer
    } else {
        issuer
    };
    Ok((issuer.to_owned(), account.to_owned()))
}

fn text(bytes: &[u8]) -> Result<&str, SkipReason> {
    if bytes.len() > MAX_TEXT_LENGTH {
        return Err(SkipReason::Invalid);
    }
    std::str::from_utf8(bytes).map_err(|_| SkipReason::Invalid)
}

/// The codes of one export, collected as they are scanned.
#[derive(Debug)]
pub struct MigrationBatch {
    id: i32,
    codes: Vec<Option<Vec<Result<ParsedUri, SkipReason>>>>,
}

impl MigrationBatch {
    pub fn new(code: MigrationCode) -> Self {
        let mut codes = Vec::new();
        codes.resize_with(code.batch_size, || None);
        codes[code.batch_index] = Some(code.entries);
        Self {
            id: code.batch_id,
            codes,
        }
    }

    /// Adds another code of the batch; `Ok(false)` for a code already
    /// scanned, which is ignored.
    pub fn add(&mut self, code: MigrationCode) -> Result<bool, ImportError> {
        if code.batch_id != self.id || code.batch_size != self.codes.len() {
            return Err(ImportError::OtherBatch);
        }
        let slot = &mut self.codes[code.batch_index];
        if slot.is_some() {
            return Ok(false);
        }
        *slot = Some(code.entries);
        Ok(true)
    }

    pub fn scanned(&self) -> usize {
        self.codes.iter().filter(|code| code.is_some()).count()
    }

    pub fn size(&self) -> usize {
        self.codes.len()
    }

    pub fn is_complete(&self) -> bool {
        self.codes.iter().all(Option::is_some)
    }

    /// The entries of all codes in batch order, numbered across codes; the
    /// batch itself back while codes are missing.
    pub fn finish(self) -> Result<Import, Self> {
        if !self.is_complete() {
            return Err(self);
        }
        let mut import = Import::default();
        for entry in self.codes.into_iter().flatten().flatten() {
            import.push(entry);
        }
        Ok(import)
    }
}
