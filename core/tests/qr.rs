//! QR decoding on frames rendered from the fixtures in `fixtures/qr`
//! (`tools/gen-qr-fixtures.sh`).

use std::path::PathBuf;

use sailfactor_core::ffi::{sf_qr_decode, sf_string_free, SfString, SF_OK};
use sailfactor_core::qr::{self, LumaFrame, QrError, MAX_PAYLOAD_LENGTH};

const TOTP_URI: &str =
    "otpauth://totp/Example:alice@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Example";
const QUIET_ZONE: usize = 4;

struct Rendering {
    module_size: usize,
    angle_degrees: f64,
    dark: u8,
    light: u8,
}

const PLAIN: Rendering = Rendering {
    module_size: 4,
    angle_degrees: 0.0,
    dark: 20,
    light: 235,
};

struct Frame {
    pixels: Vec<u8>,
    width: usize,
    height: usize,
}

fn modules(name: &str) -> Vec<Vec<bool>> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/fixtures/qr", name]
        .iter()
        .collect();
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| line.chars().map(|module| module == '#').collect())
        .collect()
}

/// Draws the code with a quiet zone, rotated about the frame's center on a
/// canvas large enough for any angle.
fn render(modules: &[Vec<bool>], rendering: &Rendering) -> Frame {
    let code_side = ((modules.len() + 2 * QUIET_ZONE) * rendering.module_size) as f64;
    let side = (code_side * std::f64::consts::SQRT_2).ceil() as usize;
    let center = side as f64 / 2.0;
    let (sin, cos) = rendering.angle_degrees.to_radians().sin_cos();
    let mut pixels = vec![rendering.light; side * side];
    for y in 0..side {
        for x in 0..side {
            let (dx, dy) = (x as f64 + 0.5 - center, y as f64 + 0.5 - center);
            let u = cos * dx + sin * dy + code_side / 2.0;
            let v = -sin * dx + cos * dy + code_side / 2.0;
            if u < 0.0 || v < 0.0 {
                continue;
            }
            let column = (u as usize / rendering.module_size).checked_sub(QUIET_ZONE);
            let row = (v as usize / rendering.module_size).checked_sub(QUIET_ZONE);
            if let (Some(column), Some(row)) = (column, row) {
                if modules.get(row).and_then(|r| r.get(column)) == Some(&true) {
                    pixels[y * side + x] = rendering.dark;
                }
            }
        }
    }
    Frame {
        pixels,
        width: side,
        height: side,
    }
}

fn decode(frame: &Frame) -> Result<String, QrError> {
    let luma = LumaFrame::new(&frame.pixels, frame.width, frame.height, frame.width, 1)?;
    qr::decode(&luma).map(|payload| String::from_utf8(payload.to_vec()).unwrap())
}

#[test]
fn decodes_an_otpauth_uri() {
    let frame = render(&modules("totp.txt"), &PLAIN);
    assert_eq!(decode(&frame).as_deref(), Ok(TOTP_URI));
}

#[test]
fn decodes_a_rotated_code() {
    let rendering = Rendering {
        angle_degrees: 30.0,
        ..PLAIN
    };
    let frame = render(&modules("totp.txt"), &rendering);
    assert_eq!(decode(&frame).as_deref(), Ok(TOTP_URI));
}

#[test]
fn decodes_a_low_contrast_code() {
    let rendering = Rendering {
        dark: 90,
        light: 150,
        ..PLAIN
    };
    let frame = render(&modules("totp.txt"), &rendering);
    assert_eq!(decode(&frame).as_deref(), Ok(TOTP_URI));
}

#[test]
fn decodes_a_large_frame_after_subsampling() {
    let rendering = Rendering {
        module_size: 60,
        ..PLAIN
    };
    let frame = render(&modules("totp.txt"), &rendering);
    assert!(frame.width > 2 * 1280);
    assert_eq!(decode(&frame).as_deref(), Ok(TOTP_URI));
}

#[test]
fn reads_luma_from_interleaved_rows_with_padding() {
    let plain = render(&modules("totp.txt"), &PLAIN);
    let (pixel_step, padding) = (2, 37);
    let row_stride = plain.width * pixel_step + padding;
    let mut pixels = vec![128u8; row_stride * plain.height];
    for y in 0..plain.height {
        for x in 0..plain.width {
            pixels[y * row_stride + x * pixel_step] = plain.pixels[y * plain.width + x];
        }
    }
    let frame = LumaFrame::new(&pixels, plain.width, plain.height, row_stride, pixel_step).unwrap();
    assert_eq!(qr::decode(&frame).unwrap().as_slice(), TOTP_URI.as_bytes());
}

#[test]
fn accepts_a_payload_at_the_limit() {
    let frame = render(&modules("max-length.txt"), &PLAIN);
    assert_eq!(
        decode(&frame).map(|payload| payload.len()),
        Ok(MAX_PAYLOAD_LENGTH)
    );
}

#[test]
fn rejects_a_payload_over_the_limit() {
    let frame = render(&modules("too-long.txt"), &PLAIN);
    assert_eq!(decode(&frame), Err(QrError::TooLong));
}

#[test]
fn rejects_a_payload_that_is_not_utf8() {
    let frame = render(&modules("invalid-utf8.txt"), &PLAIN);
    assert_eq!(decode(&frame), Err(QrError::Unreadable));
}

#[test]
fn reports_a_frame_without_a_code() {
    let frame = Frame {
        pixels: vec![200; 640 * 480],
        width: 640,
        height: 480,
    };
    assert_eq!(decode(&frame), Err(QrError::NotFound));
}

#[test]
fn rejects_invalid_frame_layouts() {
    let pixels = vec![0u8; 100 * 100];
    let invalid = [
        (0, 10, 10, 1),
        (10, 0, 10, 1),
        (4097, 1, 4097, 1),
        (10, 10, 9, 1),
        (10, 10, 10, 0),
        (10, 10, 50, 5),
        (100, 101, 100, 1),
        (50, 50, 98, 2),
        (2, 2, usize::MAX, 1),
    ];
    for (width, height, row_stride, pixel_step) in invalid {
        assert!(
            LumaFrame::new(&pixels, width, height, row_stride, pixel_step).is_err(),
            "{width}x{height}, stride {row_stride}, step {pixel_step}"
        );
    }
    assert!(LumaFrame::new(&pixels, 50, 50, 199, 4).is_ok());
}

#[test]
fn c_api_returns_the_payload() {
    let frame = render(&modules("totp.txt"), &PLAIN);
    let mut out = SfString {
        data: std::ptr::null_mut(),
        length: 0,
    };
    let side = frame.width as u32;
    // SAFETY: the frame buffer holds side * side bytes; out is a local.
    let status = unsafe {
        sf_qr_decode(
            frame.pixels.as_ptr(),
            frame.pixels.len(),
            side,
            side,
            side,
            1,
            &mut out,
        )
    };
    assert_eq!(status, SF_OK);
    // SAFETY: on success out holds length bytes owned by the core.
    let payload = unsafe { std::slice::from_raw_parts(out.data, out.length) };
    assert_eq!(payload, TOTP_URI.as_bytes());
    // SAFETY: out came from sf_qr_decode and is not used afterwards.
    unsafe { sf_string_free(out) };
}
