//! TOTP settings as KeePassXC stores them in an entry, and codes per RFC
//! 6238. Reading follows KeePassXC's documented behavior (`Totp.cpp`,
//! `Entry::updateTotp`) so the same entry shows the same code in both apps;
//! deviations are noted where they are made.

mod base32;
mod settings;
mod totp;

pub use settings::{
    parse_uri, settings_from_attributes, write_uri, ParsedUri, ATTRIBUTE_KEEPASS2_ALGORITHM,
    ATTRIBUTE_KEEPASS2_LENGTH, ATTRIBUTE_KEEPASS2_PERIOD, ATTRIBUTE_KEEPASS2_SECRET, ATTRIBUTE_OTP,
    ATTRIBUTE_SEED, ATTRIBUTE_SETTINGS, MAX_URI_LENGTH,
};
pub use totp::{code_at, seconds_remaining};

use zeroize::Zeroizing;

pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_PERIOD: u32 = 30;
pub const STEAM_DIGITS: u8 = 5;
pub const MAX_DIGITS: u8 = 10;
pub const MAX_PERIOD: u32 = 86_400;
// A seed beyond this is not a TOTP secret any service hands out; the bound
// keeps a crafted entry from making every code computation expensive.
pub const MAX_SECRET_LENGTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoder {
    Decimal,
    /// Steam Guard: characters from a 26-letter alphabet instead of digits.
    Steam,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    InvalidUri,
    InvalidSecret,
    InvalidSettings,
    /// Counter-based codes change the file with every use; not supported.
    Hotp,
    UnsupportedType,
    TooLong,
}

/// Everything needed to compute a code. The seed is kept decoded and is
/// wiped on drop; `Debug` leaves it out.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSettings {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub encoder: Encoder,
}

impl TotpSettings {
    /// Settings for a new account, checked strictly: the secret must be
    /// Base32 and digits and period inside KeePassXC's ranges.
    pub fn new(
        secret_base32: &str,
        algorithm: Algorithm,
        digits: u8,
        period: u32,
        encoder: Encoder,
    ) -> Result<Self, OtpError> {
        if !(1..=MAX_DIGITS).contains(&digits) || !(1..=MAX_PERIOD).contains(&period) {
            return Err(OtpError::InvalidSettings);
        }
        Ok(Self {
            secret: base32::decode(secret_base32)?,
            algorithm,
            digits,
            period,
            encoder,
        })
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl std::fmt::Debug for TotpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSettings")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("encoder", &self.encoder)
            .finish_non_exhaustive()
    }
}
