//! Reading TOTP settings from an entry's attributes and writing the
//! `otpauth://` URI for a new account.
//!
//! An entry carries its settings in one of three forms, read in KeePassXC's
//! order: the legacy `TOTP Settings` with `TOTP Seed`, the `otp` attribute
//! (an `otpauth://` URI or KeeOtp's `key=...&size=...` form), or KeePass
//! 2's `TimeOtp-*` attributes. Only new accounts are written, always as an
//! `otp` URI; existing attributes are never rewritten.

use zeroize::Zeroizing;

use super::{
    base32, Algorithm, Encoder, OtpError, TotpSettings, DEFAULT_DIGITS, DEFAULT_PERIOD, MAX_DIGITS,
    MAX_PERIOD, STEAM_DIGITS,
};

pub const ATTRIBUTE_OTP: &str = "otp";
pub const ATTRIBUTE_SEED: &str = "TOTP Seed";
pub const ATTRIBUTE_SETTINGS: &str = "TOTP Settings";
pub const ATTRIBUTE_KEEPASS2_SECRET: &str = "TimeOtp-Secret-Base32";
pub const ATTRIBUTE_KEEPASS2_ALGORITHM: &str = "TimeOtp-Algorithm";
pub const ATTRIBUTE_KEEPASS2_LENGTH: &str = "TimeOtp-Length";
pub const ATTRIBUTE_KEEPASS2_PERIOD: &str = "TimeOtp-Period";

pub const MAX_URI_LENGTH: usize = 2048;
const MAX_QUERY_ITEMS: usize = 32;
const STEAM_ENCODER: &str = "steam";
const LEGACY_STEAM: &str = "S";
// KeePassXC names an entry without a title after itself; SailToken does
// the same with its own name.
const UNTITLED: &str = "SailToken";
const NO_USER_NAME: &str = "none";

/// A scanned or typed `otpauth://totp/` URI. The issuer comes from the
/// `issuer` parameter, else from the label before the colon.
#[derive(Debug)]
pub struct ParsedUri {
    pub issuer: String,
    pub account: String,
    pub settings: TotpSettings,
}

/// Parses a URI for a new account. Stricter than reading an entry: only
/// the `totp` type is accepted.
pub fn parse_uri(uri: &str) -> Result<ParsedUri, OtpError> {
    let parts = UriParts::split(uri)?.ok_or(OtpError::InvalidUri)?;
    match parts.kind.to_ascii_lowercase().as_str() {
        "totp" => {}
        "hotp" => return Err(OtpError::Hotp),
        _ => return Err(OtpError::UnsupportedType),
    }
    let query = Query::parse(parts.query)?;
    let (label_issuer, account) = match split_label(parts.label) {
        Some((issuer, account)) => (
            text(&percent_decode(issuer))?,
            text(&percent_decode(account))?.trim_start().to_owned(),
        ),
        None => (String::new(), text(&percent_decode(parts.label))?),
    };
    let issuer = match query.text("issuer")? {
        Some(issuer) if !issuer.is_empty() => issuer,
        _ => label_issuer,
    };
    Ok(ParsedUri {
        issuer,
        account,
        settings: query.otpauth_settings()?,
    })
}

/// The settings an entry's attributes describe, `None` if it has none.
pub fn settings_from_attributes<'a>(
    attribute: impl Fn(&str) -> Option<&'a str>,
) -> Result<Option<TotpSettings>, OtpError> {
    let bounded = |name: &str| match attribute(name) {
        Some(value) if value.len() > MAX_URI_LENGTH => Err(OtpError::TooLong),
        value => Ok(value),
    };
    // As in KeePassXC, an empty value means no TOTP rather than a broken one.
    if let Some(settings) = bounded(ATTRIBUTE_SETTINGS)? {
        let seed = bounded(ATTRIBUTE_SEED)?.unwrap_or_default();
        if settings.is_empty() && seed.is_empty() {
            return Ok(None);
        }
        return parse_stored(settings, seed).map(Some);
    }
    if let Some(otp) = bounded(ATTRIBUTE_OTP)? {
        if otp.is_empty() {
            return Ok(None);
        }
        return parse_stored(otp, "").map(Some);
    }
    if let Some(secret) = bounded(ATTRIBUTE_KEEPASS2_SECRET)? {
        return keepass2_settings(
            secret,
            bounded(ATTRIBUTE_KEEPASS2_ALGORITHM)?,
            bounded(ATTRIBUTE_KEEPASS2_LENGTH)?,
            bounded(ATTRIBUTE_KEEPASS2_PERIOD)?,
        )
        .map(Some);
    }
    Ok(None)
}

/// The `otp` attribute for a new account, laid out as KeePassXC writes it
/// when it saves TOTP settings.
pub fn write_uri(title: &str, user_name: &str, settings: &TotpSettings) -> Zeroizing<String> {
    let title = match title {
        "" => UNTITLED.to_owned(),
        title => percent_encode(title.as_bytes()),
    };
    let user_name = match user_name {
        "" => NO_USER_NAME.to_owned(),
        user_name => percent_encode(user_name.as_bytes()),
    };
    let secret = Zeroizing::new(percent_encode(base32::encode(settings.secret()).as_bytes()));
    let period = settings.period.to_string();
    let digits = settings.digits.to_string();
    let mut parts: Vec<&str> = vec![
        "otpauth://totp/",
        &title,
        ":",
        &user_name,
        "?secret=",
        &secret,
        "&period=",
        &period,
        "&digits=",
        &digits,
        "&issuer=",
        &title,
    ];
    if settings.encoder == Encoder::Steam {
        parts.extend(["&encoder=", STEAM_ENCODER]);
    }
    match settings.algorithm {
        Algorithm::Sha1 => {}
        Algorithm::Sha256 => parts.extend(["&algorithm=", "SHA256"]),
        Algorithm::Sha512 => parts.extend(["&algorithm=", "SHA512"]),
    }
    // Sized up front so the string never reallocates and leaves an
    // unwiped copy of the secret behind.
    let mut uri = Zeroizing::new(String::with_capacity(
        parts.iter().map(|part| part.len()).sum(),
    ));
    for part in parts {
        uri.push_str(part);
    }
    uri
}

/// One stored settings value: an `otpauth://` URI, KeeOtp's query form, or
/// the legacy `step;digits` with the seed from its own attribute.
fn parse_stored(value: &str, seed: &str) -> Result<TotpSettings, OtpError> {
    if let Some(parts) = UriParts::split(value)? {
        // KeePassXC computes a TOTP code for any otpauth type; a HOTP
        // entry would show wrong codes, so it is reported instead.
        if parts.kind.eq_ignore_ascii_case("hotp") {
            return Err(OtpError::Hotp);
        }
        return Query::parse(parts.query)?.otpauth_settings();
    }
    let query = Query::parse(value)?;
    if query.has("key") {
        let key = query.secret("key")?;
        return clamped(
            &key,
            query.algorithm("otpHashMode"),
            query.number("size"),
            query.number("step"),
            Encoder::Decimal,
        );
    }
    if seed.is_empty() {
        return Err(OtpError::InvalidSecret);
    }
    match value.split(';').collect::<Vec<_>>().as_slice() {
        [_, LEGACY_STEAM, ..] => clamped(
            seed,
            Algorithm::Sha1,
            Some(u32::from(STEAM_DIGITS)),
            None,
            Encoder::Steam,
        ),
        [step, digits, ..] => clamped(
            seed,
            Algorithm::Sha1,
            Some(unsigned(digits)),
            Some(unsigned(step)),
            Encoder::Decimal,
        ),
        _ => clamped(seed, Algorithm::Sha1, None, None, Encoder::Decimal),
    }
}

/// KeePass 2 leaves out what is at its default; unlike the other forms,
/// KeePassXC does not clamp these values, and a zero makes no code.
fn keepass2_settings(
    secret: &str,
    algorithm: Option<&str>,
    length: Option<&str>,
    period: Option<&str>,
) -> Result<TotpSettings, OtpError> {
    let number = |value: Option<&str>, default: u32| match value {
        Some(value) if !value.is_empty() => unsigned(value),
        _ => default,
    };
    let digits = number(length, u32::from(DEFAULT_DIGITS));
    let period = number(period, DEFAULT_PERIOD);
    if digits == 0 || digits > u32::from(MAX_DIGITS) || period == 0 || period > MAX_PERIOD {
        return Err(OtpError::InvalidSettings);
    }
    TotpSettings::new(
        secret,
        hash_algorithm(algorithm.filter(|name| !name.is_empty())),
        digits as u8,
        period,
        Encoder::Decimal,
    )
}

/// Settings with KeePassXC's bounds applied: digits 1 to 10, period 1 to
/// 86400 seconds; an unreadable number counts as zero, which the bounds
/// turn into one.
fn clamped(
    secret: &str,
    algorithm: Algorithm,
    digits: Option<u32>,
    period: Option<u32>,
    encoder: Encoder,
) -> Result<TotpSettings, OtpError> {
    let default_digits = match encoder {
        Encoder::Decimal => DEFAULT_DIGITS,
        Encoder::Steam => STEAM_DIGITS,
    };
    let digits = digits.map_or(default_digits, |digits| {
        digits.clamp(1, u32::from(MAX_DIGITS)) as u8
    });
    let period = period.map_or(DEFAULT_PERIOD, |period| period.clamp(1, MAX_PERIOD));
    TotpSettings::new(secret, algorithm, digits, period, encoder)
}

fn hash_algorithm(name: Option<&str>) -> Algorithm {
    match name.map(str::to_ascii_uppercase).as_deref() {
        Some("SHA512" | "HMAC-SHA-512") => Algorithm::Sha512,
        Some("SHA256" | "HMAC-SHA-256") => Algorithm::Sha256,
        _ => Algorithm::Sha1,
    }
}

/// Qt's `toUInt`: a decimal number without sign or spaces, zero otherwise.
fn unsigned(text: &str) -> u32 {
    text.parse().unwrap_or(0)
}

struct UriParts<'a> {
    kind: &'a str,
    label: &'a str,
    query: &'a str,
}

impl<'a> UriParts<'a> {
    /// Splits `otpauth://kind/label?query`; `None` for anything that is not
    /// an `otpauth` URI.
    fn split(uri: &'a str) -> Result<Option<Self>, OtpError> {
        if uri.len() > MAX_URI_LENGTH {
            return Err(OtpError::TooLong);
        }
        let Some((scheme, rest)) = uri.split_once("://") else {
            return Ok(None);
        };
        if !scheme.eq_ignore_ascii_case("otpauth") {
            return Ok(None);
        }
        let rest = rest.split_once('#').map_or(rest, |(rest, _)| rest);
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (kind, label) = path.split_once('/').unwrap_or((path, ""));
        Ok(Some(Self { kind, label, query }))
    }
}

/// Query items in order; a name that appears twice counts with its first
/// value, as in `QUrlQuery`.
struct Query<'a> {
    items: Vec<(&'a str, &'a str)>,
}

impl<'a> Query<'a> {
    fn parse(query: &'a str) -> Result<Self, OtpError> {
        if query.len() > MAX_URI_LENGTH {
            return Err(OtpError::TooLong);
        }
        let items: Vec<_> = query
            .split('&')
            .filter(|item| !item.is_empty())
            .map(|item| item.split_once('=').unwrap_or((item, "")))
            .collect();
        if items.len() > MAX_QUERY_ITEMS {
            return Err(OtpError::TooLong);
        }
        Ok(Self { items })
    }

    fn has(&self, name: &str) -> bool {
        self.items.iter().any(|(key, _)| *key == name)
    }

    fn raw(&self, name: &str) -> Option<&'a str> {
        self.items
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }

    /// A value that is not a secret, decoded like `QUrlQuery` does.
    fn value(&self, name: &str) -> Option<Zeroizing<String>> {
        self.raw(name).map(|value| {
            Zeroizing::new(String::from_utf8_lossy(&percent_decode(value)).into_owned())
        })
    }

    /// A Base32 secret. Only the escapes KeePassXC itself writes, `%3D`
    /// for padding and `%20`, are decoded; any other escape is refused
    /// instead of read differently. KeePassXC's `QUrlQuery` keeps an escape
    /// encoded when it stands for `+`, a byte that is not UTF-8 or a `%`
    /// without two hex digits, and its Base32 reader then drops the `%` and
    /// keeps the hex digits as symbols, which would give both apps a
    /// plausible but different code (measured with keepassxc-cli 2.7.12).
    fn secret(&self, name: &str) -> Result<Zeroizing<String>, OtpError> {
        let value = self.raw(name).ok_or(OtpError::InvalidSecret)?;
        let bytes = value.as_bytes();
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'%' {
                let escape = bytes.get(index + 1..index + 3).unwrap_or_default();
                if !escape.eq_ignore_ascii_case(b"3D") && escape != b"20" {
                    return Err(OtpError::InvalidSecret);
                }
            }
        }
        let decoded = percent_decode(value);
        // Only ASCII was decoded, so the bytes are the UTF-8 they were.
        let text = std::str::from_utf8(&decoded).map_err(|_| OtpError::InvalidSecret)?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    fn number(&self, name: &str) -> Option<u32> {
        self.value(name).map(|value| unsigned(&value))
    }

    fn algorithm(&self, name: &str) -> Algorithm {
        hash_algorithm(self.value(name).as_ref().map(|value| value.as_str()))
    }

    fn text(&self, name: &str) -> Result<Option<String>, OtpError> {
        self.items
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| text(&percent_decode(value)))
            .transpose()
    }

    fn otpauth_settings(&self) -> Result<TotpSettings, OtpError> {
        let secret = self.secret("secret")?;
        let encoder = match self.value("encoder").as_ref().map(|value| value.as_str()) {
            Some(STEAM_ENCODER) => Encoder::Steam,
            _ => Encoder::Decimal,
        };
        // Deviation from KeePassXC: a Steam URI without `digits` gets the
        // five characters Steam uses, where KeePassXC shows six.
        clamped(
            &secret,
            self.algorithm("algorithm"),
            self.number("digits"),
            self.number("period"),
            encoder,
        )
    }
}

/// Splits `issuer:account` at the first literal colon, else at the first
/// escaped one, so a colon escaped inside the issuer (as KeePassXC writes
/// it) stays part of the issuer.
fn split_label(label: &str) -> Option<(&str, &str)> {
    if let Some(split) = label.split_once(':') {
        return Some(split);
    }
    let index = label.to_ascii_uppercase().find("%3A")?;
    Some((&label[..index], &label[index + 3..]))
}

fn text(bytes: &[u8]) -> Result<String, OtpError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| OtpError::InvalidUri)
}

/// Decodes `%XX` escapes; a `%` without two hex digits stays as it is, as
/// in Qt's tolerant parsing. `+` is not a space in a URI query.
fn percent_decode(text: &str) -> Zeroizing<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        let escaped = bytes
            .get(index + 1..index + 3)
            .filter(|_| bytes[index] == b'%')
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    decoded
}

/// Escapes everything but RFC 3986's unreserved characters, like
/// `QUrl::toPercentEncoding`.
fn percent_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
