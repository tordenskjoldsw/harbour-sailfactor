# Jolla Store listing

Settings for the Harbour submission, kept here for later updates. The
texts to paste into the form are in `docs/store/`, one paragraph or list
item per line, so the form keeps them intact. Limits are the store's.

## Title (max. 30, best under 25)

SailFactor

## Summary (max. 200)

`docs/store/summary.txt`

## Description (max. 4000)

`docs/store/description.txt`

## Recent changes (max. 2000)

`docs/store/recent-changes.txt`

## Category

Utilities.

## Binaries

Harbour asks for at least aarch64 and armv7hl, both built from the
release tag with `-c no-fix-version` and checked with `sfdk check`:

- `harbour-sailfactor-<version>-1.aarch64.rpm`:
  `sfdk -c no-fix-version -c target=SailfishOS-5.1.0.11-aarch64 build`
- `harbour-sailfactor-<version>-1.armv7hl.rpm`:
  `sfdk -c no-fix-version -c target=SailfishOS-5.1.0.11-armv7hl build`

The build is in the source tree, so remove the C++ objects, `moc_*`,
`Makefile` and the binary in the top folder before each release build:
`make` does not rebuild `main.o` when only the version changes, and the
other architecture's objects do not link. The armv7hl build is not tested
on a device.

## Compatibility

Phone. (No aarch64 tablet exists; the app supports both orientations,
except the scan page, which stays in portrait.)

## Visual assets

- Icon: `icons/172x172/harbour-sailfactor.png`
- Screenshots: at least 1080 px wide, fake data only. Taken on the Jolla
  Phone (1032 px wide, volume up and down together) with a demo file of
  made-up accounts, then scaled to 1080 px with Lanczos. Smaller copies
  for the README are in `docs/images/`.
- Cover image (optional): 1080x540, `docs/images/cover.png`: the icon
  rendered from `icons/harbour-sailfactor.svg`, the name and a screenshot,
  in Open Sans, in the style of SailVault's cover

## Contact details

- Website: https://github.com/tordenskjoldsw/harbour-sailfactor
- Privacy policy:
  https://github.com/tordenskjoldsw/harbour-sailfactor/blob/main/PRIVACY.md
- Open source project URL: https://github.com/tordenskjoldsw/harbour-sailfactor
- Email: the maintainer's contact address for Jolla (not stored here)

## Publish settings

Immediately after QA.

## Message to QA

`docs/store/qa-message.txt`
