//! Accounts waiting to be added: from a camera frame, a URI or a typed
//! secret. The confirmation page shows their issuer, name and first code
//! before `st_account_add` stores them.

use zeroize::Zeroizing;

use super::{
    bytes, decode_frame, otp_status, qr_status, unix_seconds, utf8, StPending, StString,
    ST_ALGORITHM_SHA1, ST_ALGORITHM_SHA256, ST_ALGORITHM_SHA512, ST_ENCODER_DECIMAL,
    ST_ENCODER_STEAM, ST_EXPORT_CODE, ST_INVALID_ARGUMENT, ST_OK, ST_TEXT_ISSUER, ST_TEXT_NAME,
};
use crate::import::{read_migration_uri, ImportError};
use crate::otp::{self, Algorithm, Encoder, OtpError, ParsedUri, TotpSettings};

/// Decodes the first QR code in a camera frame and reads it as an
/// `otpauth://totp/` URI; the payload never leaves the core. The frame has
/// one byte of brightness per pixel, `pixel_step` bytes (1 to 4) apart and
/// `row_stride` bytes per row, at most 4096 pixels per side.
/// `ST_NOT_FOUND`: no code in the frame; `ST_CORRUPTED`: a code that could
/// not be read; `ST_NOT_OTPAUTH`, `ST_HOTP`, `ST_UNSUPPORTED_TYPE`: a code
/// that is not a TOTP account; `ST_EXPORT_CODE`: an export code of another
/// app, for the import (`st_import_from_frame`).
///
/// # Safety
///
/// `pixels` must be valid for reads of `length` bytes; `out` valid for one
/// write. Release the result with `st_pending_free`.
#[no_mangle]
pub unsafe extern "C" fn st_pending_from_frame(
    pixels: *const u8,
    length: usize,
    width: u32,
    height: u32,
    row_stride: u32,
    pixel_step: u32,
    out: *mut *mut StPending,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(out), Some(pixels)) = (unsafe { out.as_mut() }, unsafe { bytes(pixels, length) })
    else {
        return ST_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    if pixels.is_empty() {
        return ST_INVALID_ARGUMENT;
    }
    let payload = match decode_frame(pixels, width, height, row_stride, pixel_step) {
        Ok(payload) => payload,
        Err(error) => return qr_status(error),
    };
    let uri = std::str::from_utf8(&payload).expect("the QR decoder returns UTF-8");
    if !matches!(read_migration_uri(uri), Err(ImportError::NotAnExport)) {
        return ST_EXPORT_CODE;
    }
    deliver(otp::parse_uri(uri), out)
}

/// Reads an `otpauth://totp/` URI, such as one pasted by the user.
///
/// # Safety
///
/// `uri` must be UTF-8 of `uri_length` bytes; `out` valid for one write.
/// Release the result with `st_pending_free`.
#[no_mangle]
pub unsafe extern "C" fn st_pending_from_uri(
    uri: *const u8,
    uri_length: usize,
    out: *mut *mut StPending,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(out), Some(uri)) = (unsafe { out.as_mut() }, unsafe { utf8(uri, uri_length) }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    deliver(otp::parse_uri(uri), out)
}

/// An account typed in by hand: a Base32 secret, `ST_ALGORITHM_*`, digits
/// 1 to 10, a period of 1 to 86400 seconds and `ST_ENCODER_*`. Issuer and
/// name are given to `st_account_add`.
///
/// # Safety
///
/// `secret` must be UTF-8 of `secret_length` bytes; `out` valid for one
/// write. Release the result with `st_pending_free`.
#[no_mangle]
pub unsafe extern "C" fn st_pending_from_secret(
    secret: *const u8,
    secret_length: usize,
    algorithm: u32,
    digits: u32,
    period: u32,
    encoder: u32,
    out: *mut *mut StPending,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(out), Some(secret)) = (unsafe { out.as_mut() }, unsafe {
        utf8(secret, secret_length)
    }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let algorithm = match algorithm {
        ST_ALGORITHM_SHA1 => Algorithm::Sha1,
        ST_ALGORITHM_SHA256 => Algorithm::Sha256,
        ST_ALGORITHM_SHA512 => Algorithm::Sha512,
        _ => return ST_INVALID_ARGUMENT,
    };
    let encoder = match encoder {
        ST_ENCODER_DECIMAL => Encoder::Decimal,
        ST_ENCODER_STEAM => Encoder::Steam,
        _ => return ST_INVALID_ARGUMENT,
    };
    let Ok(digits) = u8::try_from(digits) else {
        return otp_status(OtpError::InvalidSettings);
    };
    let settings = TotpSettings::new(secret, algorithm, digits, period, encoder);
    deliver(
        settings.map(|settings| ParsedUri {
            issuer: String::new(),
            account: String::new(),
            settings,
        }),
        out,
    )
}

/// The issuer (`ST_TEXT_ISSUER`) or account name (`ST_TEXT_NAME`) read
/// from the URI; empty for a typed secret.
///
/// # Safety
///
/// `pending` must be a live handle; `out` valid for one write. Release the
/// text with `st_string_free`.
#[no_mangle]
pub unsafe extern "C" fn st_pending_text(
    pending: *const StPending,
    column: u32,
    out: *mut StString,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = StString::EMPTY;
    // SAFETY: guaranteed by the caller.
    let Some(pending) = (unsafe { pending.as_ref() }) else {
        return ST_INVALID_ARGUMENT;
    };
    *out = match column {
        ST_TEXT_ISSUER => StString::new(&pending.issuer),
        ST_TEXT_NAME => StString::new(&pending.name),
        _ => return ST_INVALID_ARGUMENT,
    };
    ST_OK
}

/// The pending account's code at `now`, so the user can check it against
/// the service before saving, and the seconds until it changes.
///
/// # Safety
///
/// `pending` must be a live handle; `code_out` and `remaining_out` valid
/// for one write each. Release the code with `st_string_free`.
#[no_mangle]
pub unsafe extern "C" fn st_pending_code(
    pending: *const StPending,
    now: i64,
    code_out: *mut StString,
    remaining_out: *mut u32,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(code_out), Some(remaining_out)) =
        (unsafe { (code_out.as_mut(), remaining_out.as_mut()) })
    else {
        return ST_INVALID_ARGUMENT;
    };
    *code_out = StString::EMPTY;
    *remaining_out = 0;
    // SAFETY: guaranteed by the caller.
    let (Some(pending), Some(now)) = (unsafe { pending.as_ref() }, unix_seconds(now)) else {
        return ST_INVALID_ARGUMENT;
    };
    *code_out = StString::new(&otp::code_at(&pending.settings, now));
    *remaining_out = otp::seconds_remaining(&pending.settings, now);
    ST_OK
}

/// Releases a pending account and wipes its secret.
///
/// # Safety
///
/// `pending` must be null or a handle from this API that has not been
/// freed.
#[no_mangle]
pub unsafe extern "C" fn st_pending_free(pending: *mut StPending) {
    if !pending.is_null() {
        // SAFETY: the handle came from Box::into_raw in this module.
        drop(unsafe { Box::from_raw(pending) });
    }
}

fn deliver(parsed: Result<ParsedUri, OtpError>, out: &mut *mut StPending) -> i32 {
    match parsed {
        Ok(parsed) => {
            *out = Box::into_raw(Box::new(StPending {
                issuer: Zeroizing::new(parsed.issuer),
                name: Zeroizing::new(parsed.account),
                settings: parsed.settings,
            }));
            ST_OK
        }
        Err(error) => otp_status(error),
    }
}
