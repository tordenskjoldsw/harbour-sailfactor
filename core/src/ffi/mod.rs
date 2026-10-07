//! C API for the C++ bridge, declared in `include/sailfactor_core.h`.
//!
//! Every string handed out is zeroized by `sf_string_free`.

use std::ffi::c_char;
use std::{ptr, slice};

use zeroize::Zeroize;

use crate::qr::{self, LumaFrame, QrError};

pub const SF_OK: i32 = 0;
pub const SF_INVALID_ARGUMENT: i32 = 1;
pub const SF_CORRUPTED: i32 = 7;
pub const SF_LIMIT_EXCEEDED: i32 = 8;
pub const SF_NOT_FOUND: i32 = 9;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// Bytes owned by the core, released with `sf_string_free`.
#[repr(C)]
pub struct SfString {
    pub data: *mut u8,
    pub length: usize,
}

impl SfString {
    const EMPTY: Self = Self {
        data: ptr::null_mut(),
        length: 0,
    };

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::EMPTY;
        }
        let length = bytes.len();
        let data = Box::into_raw(Box::<[u8]>::from(bytes)).cast::<u8>();
        Self { data, length }
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
    // SAFETY: data and length come from SfString::from_bytes, which leaked
    // a boxed slice of exactly this length.
    let mut bytes =
        unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(string.data, string.length)) };
    bytes.zeroize();
}

/// Decodes the first readable QR code in a frame; see `LumaFrame` for the
/// layout. On success `out` holds the UTF-8 payload, otherwise it is empty.
///
/// # Safety
///
/// `pixels` must point to `length` readable bytes and `out` must be valid
/// for a write.
#[no_mangle]
pub unsafe extern "C" fn sf_qr_decode(
    pixels: *const u8,
    length: usize,
    width: u32,
    height: u32,
    row_stride: u32,
    pixel_step: u32,
    out: *mut SfString,
) -> i32 {
    if out.is_null() {
        return SF_INVALID_ARGUMENT;
    }
    // SAFETY: the caller guarantees that out is valid for a write.
    unsafe { out.write(SfString::EMPTY) };
    if pixels.is_null() {
        return SF_INVALID_ARGUMENT;
    }
    // SAFETY: the caller guarantees length readable bytes at pixels.
    let pixels = unsafe { slice::from_raw_parts(pixels, length) };
    let decoded = LumaFrame::new(
        pixels,
        width as usize,
        height as usize,
        row_stride as usize,
        pixel_step as usize,
    )
    .and_then(|frame| qr::decode(&frame));
    match decoded {
        Ok(payload) => {
            // SAFETY: as above.
            unsafe { out.write(SfString::from_bytes(&payload)) };
            SF_OK
        }
        Err(error) => qr_status(error),
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
    fn qr_decode_rejects_null_arguments() {
        let mut out = SfString::from_bytes(b"stale");
        let stale = out.data;
        // SAFETY: a null frame with a valid out pointer.
        let status = unsafe { sf_qr_decode(ptr::null(), 0, 1, 1, 1, 1, &mut out) };
        assert_eq!(status, SF_INVALID_ARGUMENT);
        assert!(out.data.is_null());
        // SAFETY: stale was allocated by from_bytes above.
        unsafe {
            sf_string_free(SfString {
                data: stale,
                length: 5,
            })
        };
        // SAFETY: null out pointer is checked before any write.
        let status = unsafe { sf_qr_decode([0u8].as_ptr(), 1, 1, 1, 1, 1, ptr::null_mut()) };
        assert_eq!(status, SF_INVALID_ARGUMENT);
    }

    #[test]
    fn qr_decode_reports_a_blank_frame() {
        let frame = vec![255u8; 64 * 48];
        let mut out = SfString::EMPTY;
        // SAFETY: frame holds 64 * 48 bytes and out is a local.
        let status = unsafe { sf_qr_decode(frame.as_ptr(), frame.len(), 64, 48, 64, 1, &mut out) };
        assert_eq!(status, SF_NOT_FOUND);
        assert!(out.data.is_null());
    }

    #[test]
    fn string_free_accepts_null() {
        // SAFETY: null strings are documented as ignored.
        unsafe { sf_string_free(SfString::EMPTY) };
    }
}
