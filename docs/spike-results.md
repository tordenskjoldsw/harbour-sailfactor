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

## Open

- Install on the Jolla Phone and a first launch: not done yet (needs the
  install prompt confirmed on the phone).
- Cold start baseline with `tools/measure-startup.sh`: not measured yet.
- Device OS version at the time of the first install: not recorded yet.
