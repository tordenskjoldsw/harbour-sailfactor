//! QR code detection in camera frames.
//!
//! The bridge hands over the luma plane of a frame (or any byte per pixel
//! that tracks brightness); the core finds and decodes the code. The
//! payload may hold a TOTP secret, so it is collected in a bounded buffer
//! that is wiped on drop. rqrr's own intermediate buffers are freed without
//! wiping, which is recorded in `docs/spike-results.md`.

use std::io::{self, Write};

use rqrr::PreparedImage;
use zeroize::Zeroizing;

pub const MAX_FRAME_DIMENSION: usize = 4096;
pub const MAX_PIXEL_STEP: usize = 4;
// Above the 2953 bytes a QR code holds at most, so a full export code of
// another authenticator app fits.
pub const MAX_PAYLOAD_LENGTH: usize = 4096;
// Frames with a longer side are subsampled before detection: a QR code
// held up to the camera spans far more pixels than its modules need, and
// detection time grows with the pixel count.
const DETECTION_LONG_SIDE: usize = 1280;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrError {
    InvalidFrame,
    NotFound,
    Unreadable,
    TooLong,
}

/// One byte of brightness per pixel inside a larger buffer: `pixel_step`
/// bytes between pixels (2 for the luma of packed YUYV, 4 for a channel of
/// 32-bit RGB) and `row_stride` bytes between rows.
pub struct LumaFrame<'a> {
    pixels: &'a [u8],
    width: usize,
    height: usize,
    row_stride: usize,
    pixel_step: usize,
}

impl<'a> LumaFrame<'a> {
    pub fn new(
        pixels: &'a [u8],
        width: usize,
        height: usize,
        row_stride: usize,
        pixel_step: usize,
    ) -> Result<Self, QrError> {
        let dimensions = 1..=MAX_FRAME_DIMENSION;
        if !dimensions.contains(&width)
            || !dimensions.contains(&height)
            || !(1..=MAX_PIXEL_STEP).contains(&pixel_step)
        {
            return Err(QrError::InvalidFrame);
        }
        let row_bytes = (width - 1) * pixel_step + 1;
        let required = (height - 1)
            .checked_mul(row_stride)
            .and_then(|bytes| bytes.checked_add(row_bytes))
            .ok_or(QrError::InvalidFrame)?;
        if row_stride < row_bytes || pixels.len() < required {
            return Err(QrError::InvalidFrame);
        }
        Ok(Self {
            pixels,
            width,
            height,
            row_stride,
            pixel_step,
        })
    }

    fn luma(&self, x: usize, y: usize) -> u8 {
        self.pixels[y * self.row_stride + x * self.pixel_step]
    }
}

/// Decodes the first readable QR code in the frame. The payload is UTF-8
/// text of at most `MAX_PAYLOAD_LENGTH` bytes.
pub fn decode(frame: &LumaFrame) -> Result<Zeroizing<Vec<u8>>, QrError> {
    let scale = frame.width.max(frame.height).div_ceil(DETECTION_LONG_SIDE);
    let mut image = PreparedImage::prepare_from_greyscale(
        frame.width.div_ceil(scale),
        frame.height.div_ceil(scale),
        |x, y| frame.luma(x * scale, y * scale),
    );
    let grids = image.detect_grids();
    if grids.is_empty() {
        return Err(QrError::NotFound);
    }

    let mut failure = QrError::Unreadable;
    for grid in grids {
        let mut payload = PayloadWriter::new();
        let decoded = grid.decode_to(&mut payload);
        if payload.overflowed {
            failure = QrError::TooLong;
        } else if decoded.is_ok() && std::str::from_utf8(&payload.bytes).is_ok() {
            return Ok(payload.bytes);
        }
    }
    Err(failure)
}

/// Collects the payload without ever reallocating, so no unwiped copy is
/// left behind, and refuses anything beyond the payload limit.
struct PayloadWriter {
    bytes: Zeroizing<Vec<u8>>,
    overflowed: bool,
}

impl PayloadWriter {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(MAX_PAYLOAD_LENGTH)),
            overflowed: false,
        }
    }
}

impl Write for PayloadWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > MAX_PAYLOAD_LENGTH - self.bytes.len() {
            self.overflowed = true;
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
