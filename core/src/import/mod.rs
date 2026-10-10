//! Reading the accounts other authenticator apps export
//! (`docs/import-formats.md`). Every reader takes untrusted bytes, checks
//! hard limits and returns candidates; nothing reaches the file until the
//! user has chosen which to add.

mod migration;
mod protobuf;

pub use migration::{
    read_migration_uri, MigrationBatch, MigrationCode, MAX_BATCH_SIZE, MAX_MIGRATION_PAYLOAD,
};

use crate::otp::{OtpError, ParsedUri};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// Not an export this reader knows, such as an ordinary account code.
    NotAnExport,
    Malformed,
    TooLarge,
    /// A code of another export, scanned while one is being collected.
    OtherBatch,
}

/// Why an entry of an export is not taken over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// SailToken refuses new counter-based accounts (`PLAN.md` section 4).
    Hotp,
    /// An algorithm, length or OTP type SailToken does not compute.
    Unsupported,
    Invalid,
}

impl From<OtpError> for SkipReason {
    fn from(error: OtpError) -> Self {
        match error {
            OtpError::Hotp => Self::Hotp,
            OtpError::UnsupportedType => Self::Unsupported,
            OtpError::InvalidUri
            | OtpError::InvalidSecret
            | OtpError::InvalidSettings
            | OtpError::TooLong => Self::Invalid,
        }
    }
}

/// An entry that is not taken over. The position counts from 1 in the
/// export's own order, so the user can find it in the old app without the
/// core ever showing its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skipped {
    pub position: usize,
    pub reason: SkipReason,
}

/// Everything an export holds, split into accounts to offer and entries
/// that are skipped.
#[derive(Debug, Default)]
pub struct Import {
    pub accounts: Vec<ParsedUri>,
    pub skipped: Vec<Skipped>,
}

impl Import {
    fn push(&mut self, entry: Result<ParsedUri, SkipReason>) {
        match entry {
            Ok(account) => self.accounts.push(account),
            Err(reason) => self.skipped.push(Skipped {
                position: self.accounts.len() + self.skipped.len() + 1,
                reason,
            }),
        }
    }
}
