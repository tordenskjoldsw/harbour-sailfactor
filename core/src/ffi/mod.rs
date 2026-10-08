//! C API for the C++ bridge, declared in `include/sailfactor_core.h`.
//!
//! The database and accounts waiting to be added stay in Rust behind
//! opaque handles. Seeds never leave the core: the bridge gets issuers,
//! account names, codes and the seconds left. Every string handed out is
//! wiped by `sf_string_free`.

pub mod accounts;
pub mod database;
pub mod pending;

use std::ffi::c_char;
use std::{ptr, slice};

use zeroize::Zeroize;

use crate::accounts::{Account, AccountError, UUID_LENGTH};
use crate::kdbx::{Database, KdbxError};
use crate::otp::{OtpError, TotpSettings};
use crate::qr::QrError;

pub const SF_OK: i32 = 0;
pub const SF_INVALID_ARGUMENT: i32 = 1;
pub const SF_NOT_KDBX: i32 = 2;
pub const SF_UNSUPPORTED_FORMAT: i32 = 4;
pub const SF_INVALID_CREDENTIALS: i32 = 5;
pub const SF_INVALID_KEY_FILE: i32 = 6;
pub const SF_CORRUPTED: i32 = 7;
pub const SF_LIMIT_EXCEEDED: i32 = 8;
pub const SF_NOT_FOUND: i32 = 9;
pub const SF_WRITE_FAILED: i32 = 10;
pub const SF_RANDOM_UNAVAILABLE: i32 = 11;
pub const SF_NOT_OTPAUTH: i32 = 12;
pub const SF_HOTP: i32 = 13;
pub const SF_UNSUPPORTED_TYPE: i32 = 14;
pub const SF_INVALID_SECRET: i32 = 15;
pub const SF_INVALID_SETTINGS: i32 = 16;
pub const SF_NO_CODE: i32 = 17;

pub const SF_TEXT_ISSUER: u32 = 0;
pub const SF_TEXT_NAME: u32 = 1;

pub const SF_KIND_TOTP: u32 = 0;
pub const SF_KIND_HOTP: u32 = 1;
pub const SF_KIND_UNREADABLE: u32 = 2;
pub const SF_KIND_NO_CODE: u32 = 3;

pub const SF_ALGORITHM_SHA1: u32 = 0;
pub const SF_ALGORITHM_SHA256: u32 = 1;
pub const SF_ALGORITHM_SHA512: u32 = 2;

pub const SF_ENCODER_DECIMAL: u32 = 0;
pub const SF_ENCODER_STEAM: u32 = 1;

pub const SF_KDF_STANDARD: u32 = 0;
pub const SF_KDF_HIGH: u32 = 1;
pub const SF_KDF_MAXIMUM: u32 = 2;

pub const SF_UUID_LENGTH: usize = UUID_LENGTH;
pub const SF_MAX_FRAME_DIMENSION: u32 = crate::qr::MAX_FRAME_DIMENSION as u32;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

pub struct SfDatabase {
    database: Database,
}

/// A scanned or typed account before it is added: what the confirmation
/// page shows, and the settings to store.
pub struct SfPending {
    issuer: zeroize::Zeroizing<String>,
    name: zeroize::Zeroizing<String>,
    settings: TotpSettings,
}

pub struct SfAccountList {
    accounts: Vec<Account>,
}

// The bridge opens, saves and scans on worker threads and uses the results
// on the main thread, so the handles must stay Send and Sync.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SfDatabase>();
    assert_send_sync::<SfPending>();
    assert_send_sync::<SfAccountList>();
};

/// Text owned by the core; release it with `sf_string_free`.
#[repr(C)]
pub struct SfString {
    pub data: *mut u8,
    pub length: usize,
}

impl SfString {
    pub const EMPTY: Self = Self {
        data: ptr::null_mut(),
        length: 0,
    };

    fn new(text: &str) -> Self {
        if text.is_empty() {
            return Self::EMPTY;
        }
        let length = text.len();
        let data = Box::into_raw(Box::<[u8]>::from(text.as_bytes())).cast::<u8>();
        Self { data, length }
    }
}

/// A serialized database file; release it with `sf_bytes_free`.
#[repr(C)]
pub struct SfBytes {
    pub data: *mut u8,
    pub length: usize,
}

impl SfBytes {
    pub const EMPTY: Self = Self {
        data: ptr::null_mut(),
        length: 0,
    };

    fn new(bytes: Vec<u8>) -> Self {
        let boxed = bytes.into_boxed_slice();
        let length = boxed.len();
        Self {
            data: Box::into_raw(boxed).cast(),
            length,
        }
    }
}

/// The core's version as a static, NUL-terminated string; never freed.
#[no_mangle]
pub extern "C" fn sf_core_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Wipes and releases a string from the core. Null strings are ignored.
///
/// # Safety
///
/// `string` must come from the core and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn sf_string_free(string: SfString) {
    if string.data.is_null() {
        return;
    }
    // SAFETY: data and length come from SfString::new, which leaked a boxed
    // slice of exactly this length.
    let mut bytes =
        unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(string.data, string.length)) };
    bytes.zeroize();
}

/// Releases a file from `sf_database_save` or `sf_database_create`.
///
/// # Safety
///
/// `bytes` must come from the core and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn sf_bytes_free(bytes: SfBytes) {
    if !bytes.data.is_null() {
        // SAFETY: data and length come from SfBytes::new.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(bytes.data, bytes.length)) });
    }
}

fn kdbx_status(error: KdbxError) -> i32 {
    match error {
        KdbxError::NotKdbx => SF_NOT_KDBX,
        KdbxError::UnsupportedVersion { .. }
        | KdbxError::UnsupportedCipher
        | KdbxError::UnsupportedCompression
        | KdbxError::UnsupportedKdf => SF_UNSUPPORTED_FORMAT,
        KdbxError::InvalidCredentials => SF_INVALID_CREDENTIALS,
        KdbxError::InvalidKeyFile => SF_INVALID_KEY_FILE,
        KdbxError::KdfParametersOutOfRange | KdbxError::LimitExceeded(_) => SF_LIMIT_EXCEEDED,
        KdbxError::InvalidHeader(_)
        | KdbxError::HeaderCorrupted
        | KdbxError::PayloadCorrupted
        | KdbxError::DecryptionFailed
        | KdbxError::DecompressionFailed
        | KdbxError::InvalidInnerHeader(_)
        | KdbxError::InvalidXml(_) => SF_CORRUPTED,
        KdbxError::CompressionFailed
        | KdbxError::EncryptionFailed
        | KdbxError::WriteVerificationFailed => SF_WRITE_FAILED,
        KdbxError::RandomUnavailable => SF_RANDOM_UNAVAILABLE,
        KdbxError::InvalidEntry(_)
        | KdbxError::InvalidGroup(_)
        | KdbxError::RootGroupProtected
        | KdbxError::NotInRecycleBin => SF_INVALID_ARGUMENT,
        KdbxError::UnknownGroup | KdbxError::UnknownEntry => SF_NOT_FOUND,
    }
}

fn otp_status(error: OtpError) -> i32 {
    match error {
        OtpError::InvalidUri => SF_NOT_OTPAUTH,
        OtpError::InvalidSecret => SF_INVALID_SECRET,
        OtpError::InvalidSettings => SF_INVALID_SETTINGS,
        OtpError::Hotp => SF_HOTP,
        OtpError::UnsupportedType => SF_UNSUPPORTED_TYPE,
        OtpError::TooLong => SF_LIMIT_EXCEEDED,
    }
}

fn account_status(error: AccountError) -> i32 {
    match error {
        AccountError::Kdbx(error) => kdbx_status(error),
        AccountError::Otp(error) => otp_status(error),
        AccountError::NoCode => SF_NO_CODE,
    }
}

fn qr_status(error: QrError) -> i32 {
    match error {
        QrError::InvalidFrame => SF_INVALID_ARGUMENT,
        QrError::NotFound => SF_NOT_FOUND,
        QrError::Unreadable => SF_CORRUPTED,
        QrError::TooLong => SF_LIMIT_EXCEEDED,
    }
}

/// Seconds since the Unix epoch; codes are not computed before it.
fn unix_seconds(now: i64) -> Option<u64> {
    u64::try_from(now).ok()
}

/// # Safety
///
/// `data` must be null or valid for reads of `length` bytes.
unsafe fn bytes<'a>(data: *const u8, length: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        (length == 0).then_some(&[][..])
    } else {
        // SAFETY: guaranteed by the caller.
        Some(unsafe { slice::from_raw_parts(data, length) })
    }
}

/// # Safety
///
/// As for `bytes`; the bytes must also be UTF-8.
unsafe fn utf8<'a>(data: *const u8, length: usize) -> Option<&'a str> {
    // SAFETY: guaranteed by the caller.
    unsafe { bytes(data, length) }.and_then(|bytes| std::str::from_utf8(bytes).ok())
}

/// # Safety
///
/// `uuid` must be null or valid for reads of 16 bytes.
unsafe fn read_uuid(uuid: *const u8) -> Option<[u8; UUID_LENGTH]> {
    if uuid.is_null() {
        return None;
    }
    let mut copy = [0u8; UUID_LENGTH];
    // SAFETY: guaranteed by the caller.
    copy.copy_from_slice(unsafe { slice::from_raw_parts(uuid, UUID_LENGTH) });
    Some(copy)
}

/// # Safety
///
/// `out` must be valid for writes of 16 bytes.
unsafe fn write_uuid(out: *mut u8, uuid: &[u8; UUID_LENGTH]) {
    // SAFETY: guaranteed by the caller.
    unsafe { slice::from_raw_parts_mut(out, UUID_LENGTH) }.copy_from_slice(uuid);
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn version_is_the_package_version() {
        // SAFETY: sf_core_version returns a pointer to a static C string.
        let version = unsafe { CStr::from_ptr(sf_core_version()) };
        assert_eq!(version.to_str(), Ok(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn free_functions_accept_null() {
        // SAFETY: null strings and files are documented as ignored.
        unsafe {
            sf_string_free(SfString::EMPTY);
            sf_bytes_free(SfBytes::EMPTY);
        }
    }

    #[test]
    fn strings_round_trip_their_bytes() {
        let string = SfString::new("issuer: äöü");
        // SAFETY: string holds length bytes owned by the core.
        let text = unsafe { slice::from_raw_parts(string.data, string.length) };
        assert_eq!(text, "issuer: äöü".as_bytes());
        // SAFETY: string came from SfString::new and is not used afterwards.
        unsafe { sf_string_free(string) };
        assert!(SfString::new("").data.is_null());
    }

    #[test]
    fn negative_times_are_refused() {
        assert_eq!(unix_seconds(-1), None);
        assert_eq!(unix_seconds(59), Some(59));
    }
}
