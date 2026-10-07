# Spike and measurement results

Results of the spikes and measurements from `PLAN.md` section 11, newest
phase last. Device results are marked as such; everything else was run on
the host.

## SDK and build target (Phase 0, 2026-10-07)

- Sailfish SDK 3.13.5, build targets `SailfishOS-5.1.0.11-aarch64` and
  `SailfishOS-5.1.0.11-armv7hl`, the same as SailVault's.
- Rust in the targets: 1.75. The host runs the core tests with Rust 1.97
  and 1.75; both pass.
- qmake builds the core with `cargo build --release --offline --locked`
  and an explicit target triple, then links `libsailfactor_core.a`
  statically. The core has no dependencies yet, so the vendored sources
  are not exercised; Phase 1 adds the first crate.
- The armv7hl build needs the top-level objects, `Makefile` and binary of
  the aarch64 build removed first (in-tree build, as in SailVault).

## Harbour validator (Phase 0, 2026-10-07)

`sfdk check` (RPM Validation script v1.110, rpmlint 2.0.0) on
`harbour-sailfactor-0.1.0-1` built with `-c no-fix-version`:

| Architecture | Validator | rpmlint |
|--------------|-----------|---------|
| aarch64 | passed | `E: no-changelogname-tag` |
| armv7hl | passed | `E: no-changelogname-tag` |

The rpmlint error is reported as a warning (`TreatErrorsAsWarnings`). It
goes away with the first entry in `rpm/harbour-sailfactor.changes`, which
is written for the 0.1.0 release.

Hardening, checked with `readelf` in both RPMs: a `GNU_RELRO` segment with
`BIND_NOW` (`FLAGS_1: NOW PIE`), no `.symtab` section. Package size about
42 KB for each architecture.

## On the device (Phase 0, 2026-10-07)

Jolla Phone (2026), Sailfish OS 5.2.0.18. `sfdk deploy --sdk` installs
the aarch64 RPM after the prompt on the phone is confirmed. It sends every
RPM in `RPMS/`, so an armv7hl package left there fails with "wrong
architecture" (code 29); keep only the package for the device in
`RPMS/` when deploying.

Verified on the device: the app installs, starts and shows its page.

## Cold start baseline (Phase 0, 2026-10-07)

`tools/measure-startup.sh`, 11 launches of the 0.1.0 build, from launch to
the first frame (`CLOCK_BOOTTIME`, `--startup-trace`). The screen must stay
on for the whole run; a first attempt stopped when the phone went to
sleep.

| Run | Time |
|-----|------|
| First launch | 480 ms |
| Launches 2 to 11, median | 436 ms |
| Launches 2 to 11, min / max | 408 ms / 467 ms |
| Launches 2 to 11, mean | 434 ms |

This is the empty-app baseline for criterion 6 (unlock page visible
< 1 s after the tap); later phases measure against it.

## Camera and QR (Phase 1, 2026-10-07)

Jolla Phone (2026), Sailfish OS 5.2.0.18, back camera, `Camera` and
`VideoOutput` from QtMultimedia 5.6 in QML, a `QAbstractVideoFilter` in
C++ and rqrr 0.10 in the core. The test code is a made-up
`otpauth://totp/` link of 79 bytes, shown on a computer screen in room
light in the evening.

### What the camera delivers

Verified on the device:

- The first launch with the `Camera` permission showed Sailjail's prompt
  for camera access; the camera worked after it was allowed.
- Frames arrive as `Format_BGRA32` with `GLTextureHandle`, one plane.
  `QVideoFrame::map` works on them inside the sandbox; the fallback to
  still captures is not needed.
- The default viewfinder size is 2560 x 1440 (10240 bytes per line). The
  camera offers 26 sizes from 160 x 96 to 2560 x 1440, among them
  1280 x 720 (5120 bytes per line).
- The viewfinder runs at about 18 to 26 frames per second in room light,
  with or without scanning; the rate follows the exposure more than the
  decoding.
- Every scan found the code and reported the right payload length.

### Measurements

Map is the time `QVideoFrame::map` takes on the render thread, decode the
time of `sf_qr_decode` (frames above 1280 pixels are subsampled to 1280 x
720 first). Time to code runs from the camera becoming active to the
first decoded code, so it includes the camera start and aiming the phone.

| Viewfinder | Decoded frames | Time to code | Map, mean / max | Decode, mean / max | Decodes until found |
|------------|----------------|--------------|-----------------|--------------------|---------------------|
| 2560 x 1440 | every 4th | 2238 ms | not measured | 28 / 35 ms | 7 |
| 2560 x 1440 | every 4th | 2563 ms | 17 / 25 ms | 26 / 35 ms | 9 |
| 2560 x 1440 | every 2nd | 2046 ms | 15 / 20 ms | 24 / 33 ms | 21 |
| 2560 x 1440 | every 4th | 1849 ms | 15 / 19 ms | 29 / 36 ms | 4 |
| 1280 x 720 | every 4th | 1846 ms | 5 / 6 ms | 34 / 37 ms | 4 |
| 1280 x 720 | every 2nd | 1387 ms | 5 / 6 ms | 25 / 27 ms | 3 |

### Decisions

- Viewfinder at 1280 x 720, every second frame decoded: mapping takes a
  third of the time of 2560 x 1440, the decoder sees the same 1280 x 720
  image either way, and this setting found the code fastest. The spike
  page starts with it.
- About 30 ms per decoded frame is too long for the render thread at 20
  frames per second. Phase 3 maps the frame on the render thread (the GL
  texture needs it), copies one channel into a buffer and decodes on a
  worker thread, skipping frames while the worker is busy.
- rqrr frees its intermediate buffers, which hold the decoded bits,
  without wiping them. The payload itself is collected in a wiped buffer.
  Accepted for now: the same code is visible in the camera frames, which
  the camera stack owns; the threat model records it in Phase 3.

### Open

- Decoding every frame at 1280 x 720.
- The viewfinder shows the camera image only in a band across the middle
  of the page; the scan page in Phase 3 lays it out properly.
