//! Accounts waiting to be added: from a camera frame, a URI or a typed
//! secret. The confirmation page shows their issuer, name and first code
//! before `sf_account_add` stores them.

use zeroize::Zeroizing;

use super::{
    bytes, otp_status, qr_status, unix_seconds, utf8, SfPending, SfString, SF_ALGORITHM_SHA1,
    SF_ALGORITHM_SHA256, SF_ALGORITHM_SHA512, SF_ENCODER_DECIMAL, SF_ENCODER_STEAM,
    SF_INVALID_ARGUMENT, SF_OK, SF_TEXT_ISSUER, SF_TEXT_NAME,
};
use crate::otp::{self, Algorithm, Encoder, OtpError, ParsedUri, TotpSettings};
use crate::qr::{self, LumaFrame};

/// Decodes the first QR code in a camera frame and reads it as an
/// `otpauth://totp/` URI; the payload never leaves the core. The frame has
/// one byte of brightness per pixel, `pixel_step` bytes (1 to 4) apart and
/// `row_stride` bytes per row, at most 4096 pixels per side.
/// `SF_NOT_FOUND`: no code in the frame; `SF_CORRUPTED`: a code that could
/// not be read; `SF_NOT_OTPAUTH`, `SF_HOTP`, `SF_UNSUPPORTED_TYPE`: a code
/// that is not a TOTP account.
///
/// # Safety
///
/// `pixels` must be valid for reads of `length` bytes; `out` valid for one
/// write. Release the result with `sf_pending_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_pending_from_frame(
    pixels: *const u8,
    length: usize,
    width: u32,
    height: u32,
    row_stride: u32,
    pixel_step: u32,
    out: *mut *mut SfPending,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(out), Some(pixels)) = (unsafe { out.as_mut() }, unsafe { bytes(pixels, length) })
    else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    if pixels.is_empty() {
        return SF_INVALID_ARGUMENT;
    }
    let payload = match LumaFrame::new(
        pixels,
        width as usize,
        height as usize,
        row_stride as usize,
        pixel_step as usize,
    )
    .and_then(|frame| qr::decode(&frame))
    {
        Ok(payload) => payload,
        Err(error) => return qr_status(error),
    };
    let uri = std::str::from_utf8(&payload).expect("the QR decoder returns UTF-8");
    deliver(otp::parse_uri(uri), out)
}

/// Reads an `otpauth://totp/` URI, such as one pasted by the user.
///
/// # Safety
///
/// `uri` must be UTF-8 of `uri_length` bytes; `out` valid for one write.
/// Release the result with `sf_pending_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_pending_from_uri(
    uri: *const u8,
    uri_length: usize,
    out: *mut *mut SfPending,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(out), Some(uri)) = (unsafe { out.as_mut() }, unsafe { utf8(uri, uri_length) }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    deliver(otp::parse_uri(uri), out)
}

/// An account typed in by hand: a Base32 secret, `SF_ALGORITHM_*`, digits
/// 1 to 10, a period of 1 to 86400 seconds and `SF_ENCODER_*`. Issuer and
/// name are given to `sf_account_add`.
///
/// # Safety
///
/// `secret` must be UTF-8 of `secret_length` bytes; `out` valid for one
/// write. Release the result with `sf_pending_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_pending_from_secret(
    secret: *const u8,
    secret_length: usize,
    algorithm: u32,
    digits: u32,
    period: u32,
    encoder: u32,
    out: *mut *mut SfPending,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(out), Some(secret)) = (unsafe { out.as_mut() }, unsafe {
        utf8(secret, secret_length)
    }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let algorithm = match algorithm {
        SF_ALGORITHM_SHA1 => Algorithm::Sha1,
        SF_ALGORITHM_SHA256 => Algorithm::Sha256,
        SF_ALGORITHM_SHA512 => Algorithm::Sha512,
        _ => return SF_INVALID_ARGUMENT,
    };
    let encoder = match encoder {
        SF_ENCODER_DECIMAL => Encoder::Decimal,
        SF_ENCODER_STEAM => Encoder::Steam,
        _ => return SF_INVALID_ARGUMENT,
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

/// The issuer (`SF_TEXT_ISSUER`) or account name (`SF_TEXT_NAME`) read
/// from the URI; empty for a typed secret.
///
/// # Safety
///
/// `pending` must be a live handle; `out` valid for one write. Release the
/// text with `sf_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_pending_text(
    pending: *const SfPending,
    column: u32,
    out: *mut SfString,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = SfString::EMPTY;
    // SAFETY: guaranteed by the caller.
    let Some(pending) = (unsafe { pending.as_ref() }) else {
        return SF_INVALID_ARGUMENT;
    };
    *out = match column {
        SF_TEXT_ISSUER => SfString::new(&pending.issuer),
        SF_TEXT_NAME => SfString::new(&pending.name),
        _ => return SF_INVALID_ARGUMENT,
    };
    SF_OK
}

/// The pending account's code at `now`, so the user can check it against
/// the service before saving, and the seconds until it changes.
///
/// # Safety
///
/// `pending` must be a live handle; `code_out` and `remaining_out` valid
/// for one write each. Release the code with `sf_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sf_pending_code(
    pending: *const SfPending,
    now: i64,
    code_out: *mut SfString,
    remaining_out: *mut u32,
) -> i32 {
    // SAFETY: guaranteed by the caller.
    let (Some(code_out), Some(remaining_out)) =
        (unsafe { (code_out.as_mut(), remaining_out.as_mut()) })
    else {
        return SF_INVALID_ARGUMENT;
    };
    *code_out = SfString::EMPTY;
    *remaining_out = 0;
    // SAFETY: guaranteed by the caller.
    let (Some(pending), Some(now)) = (unsafe { pending.as_ref() }, unix_seconds(now)) else {
        return SF_INVALID_ARGUMENT;
    };
    *code_out = SfString::new(&otp::code_at(&pending.settings, now));
    *remaining_out = otp::seconds_remaining(&pending.settings, now);
    SF_OK
}

/// Releases a pending account and wipes its secret.
///
/// # Safety
///
/// `pending` must be null or a handle from this API that has not been
/// freed.
#[no_mangle]
pub unsafe extern "C" fn sf_pending_free(pending: *mut SfPending) {
    if !pending.is_null() {
        // SAFETY: the handle came from Box::into_raw in this module.
        drop(unsafe { Box::from_raw(pending) });
    }
}

fn deliver(parsed: Result<ParsedUri, OtpError>, out: &mut *mut SfPending) -> i32 {
    match parsed {
        Ok(parsed) => {
            *out = Box::into_raw(Box::new(SfPending {
                issuer: Zeroizing::new(parsed.issuer),
                name: Zeroizing::new(parsed.account),
                settings: parsed.settings,
            }));
            SF_OK
        }
        Err(error) => otp_status(error),
    }
}
