# SailFactor - Project Plan

Status: 2026-10-07 - Phase 0 done: the scaffold builds for aarch64 and
armv7hl, passes the Harbour validator and runs on the Jolla Phone (cold
start 436 ms median, `docs/spike-results.md`). Next: Phase 1. The name was
chosen on 2026-10-07; a dormant GitHub repository `lanurmi/sailfactor` (an
integer factoring tool, last commit 2014, never in a store) shares it,
OpenRepos has no match, the Jolla Store was not searchable without an
account.

SailFactor is the "separate authenticator app" that SailVault's plan
(section 4 there) left for a later, independent project. It shares no
code repository with SailVault; the KDBX code is copied in, see section 5.

## 1. Goal

A native, open-source TOTP authenticator for Sailfish OS, published in the
Jolla Harbour store, that keeps the second factor out of the password
manager. Accounts are added by scanning a QR code with the camera or by
typing the secret. Codes are generated every 30 seconds following RFC 6238.
The accounts live in a standard KeePass KDBX4 file with KeePassXC's `otp`
attribute, so KeePassXC on a PC can open the file, and the file syncs to
the user's Nextcloud like SailVault's database.

- Package name: `harbour-sailfactor`
- Primary target: Jolla Phone (2026), aarch64, Sailfish OS 5.2
- Secondary target: armv7hl (Harbour requires it), then i486 (emulator)

## 2. Success criteria

| # | Criterion | Measured by |
|---|-----------|-------------|
| 1 | In Harbour | RPM passes the Harbour validator for aarch64 and armv7hl; Jolla QA accepts it |
| 2 | Correct codes | Every RFC 6238 and RFC 4226 test vector passes; codes match KeePassXC and a reference authenticator for the same `otpauth://` URI on the device |
| 3 | Secure unlock | The file unlocks with a master password (and optional key file); the KDF runs in the Rust core off the UI thread; key material and secrets stay in the core and are zeroized on lock; nothing on disk unlocks the file without the password |
| 4 | Lossless KeePassXC round trip | A file written by SailFactor opens in KeePassXC and shows the same codes; a file edited by KeePassXC (new entry with TOTP, renamed entry) reopens in SailFactor with nothing lost |
| 5 | No data loss on sync | Concurrent edits on phone and PC merge like KeePassXC; the phone never overwrites a changed remote file without merging |
| 6 | Fast daily use | Unlock page visible < 1 s after tap; code list visible < 0.3 s after key derivation; a scanned QR code is recognized within 2 s in daylight |
| 7 | Native UI | Silica components only; passes the Sailfish UI "Definition of Done" checklist |

## 3. Positioning (as of 2026-10)

Guiding principle, inherited from SailVault: security is never traded for
features. A convenience that weakens the security model is not built, or
only as an explicit, documented opt-in.

Authenticators on Sailfish (desk research 2026-10-07, not tested
first-hand):

| App | State | Gap |
|-----|-------|-----|
| SailOTP (Harbour) | BSD-3; QR scan with a bundled QZXing; runs on 5.0, forum posts call it unmaintained | Own storage format, no encrypted file, no sync, no PC client |
| Foil Auth (OpenRepos) | Active (1.1.17, 2026-08); encrypted with Foil | Not in the Jolla Store since 2019; own format, no sync |
| ownKeepass 2.x (Chum), KeePassRX (OpenRepos) | TOTP inside the password manager | Second factor next to the password; not in Harbour |

SailFactor competes on:

- **Separation**: the second factor lives in its own encrypted file with
  its own master password, not in the password manager
- **Standard format**: a KDBX4 file that KeePassXC opens; the file is the
  backup, and the PC can show a code when the phone is lost
- **Sync without a server product**: the file on the user's Nextcloud,
  merged like KeePassXC
- **Trust**: open source, documented threat model, no network except the
  user's own Nextcloud
- **Sailfish-native UX**: Silica conventions

What the separation gives and does not give, stated plainly in the docs:
it protects the second factor when the vault file or the vault's master
password leaks. It does not protect against a compromised phone, which
holds both apps and both factors.

## 4. Non-goals

- HOTP (counter-based codes): every code changes the file, which fights the
  sync and the merge; KeePassXC's `Totp.cpp` has no counter support either
  (checked 2026-10-07). Entries with a HOTP URI are kept losslessly and
  shown as "not supported"
- Autofill into other apps or the browser (no Sailfish API, no daemons)
- Background or scheduled sync (Harbour allows no background services)
- Time correction over the network (NTP): the phone's clock is used; a
  wrong clock gives wrong codes, and the app says so when a code is
  rejected (section 14)
- A server-side account of any kind; Bitwarden/Vaultwarden
- Fingerprint unlock (not reachable from a Harbour app, see SailVault's
  `docs/spike-results.md`)
- Codes on the cover or on the lock screen
- Opening SailVault's database from SailFactor: the point is the
  separation; moving `otp` attributes from the vault into SailFactor is an
  import (Phase 7), never a live link

## 5. Architecture

```
+--------------------------------------------------+
| QML / Silica UI                                  |
|  - camera viewfinder (QtMultimedia 5.6)          |
+--------------------------------------------------+
| C++ bridge (Qt 5.6)                              |
|  - video filter: luma plane of each frame to the |
|    core for QR detection                         |
|  - QObject models, countdown clock               |
|  - file I/O: atomic save, backups                |
|  - WebDAV to Nextcloud via QNetworkAccessManager |
+--------------------------------------------------+
| Rust core (static lib, C FFI, no I/O)            |
|  - KDBX4 codec and merge (copied from SailVault) |
|  - otpauth URI parser and writer                 |
|  - TOTP (RFC 6238): SHA-1/256/512, 1-10 digits,  |
|    Steam alphabet                                |
|  - QR detection (rqrr)                           |
+--------------------------------------------------+
```

| Decision | Rationale |
|----------|-----------|
| Rust core as static library, no I/O | Same reasons as SailVault: memory safety for parsing and crypto, `zeroize`, host-testable, nothing for the validator to see |
| KDBX code copied from SailVault, not shared as a crate | Decided 2026-10-07: both apps stay standalone repositories; a fix in one is ported to the other by hand. The copy is recorded by SailVault commit and file list (section 14), and `tools/diff-sailvault-core.sh` shows the drift |
| What is copied | `core/src/kdbx/`, `secret.rs`, `random.rs`, `argon2_memory.rs`, the KDBX fixtures with their README and `tools/gen-kdbx-fixtures.sh`. Not copied: `bitwarden`, `ffi`, `password` (SailFactor gets its own slim FFI) |
| TOTP on RustCrypto `hmac` with `sha1` and `sha2` | Established crates; `hmac` and `sha2` are already in the copied code, `sha1` is new (MSRV check pending). Test vectors from RFC 6238 appendix B and RFC 4226 appendix D |
| QR detection with `rqrr` 0.10 in the core | Pure Rust, `(MIT OR Apache-2.0) AND ISC`, MSRV 1.64 (0.11 needs 1.85); without the `img` feature it only pulls `g2p` and `lru` 0.16 (MSRV 1.70). The C++ side hands over a grayscale buffer, so the core keeps its no-I/O rule |
| Camera through QtMultimedia 5.6 | `QtMultimedia 5.6`, `libQt5Multimedia.so.5` and the Sailjail permission `Camera` are allowed (validator `allowed_permissions.conf` and the Allowed APIs page, checked 2026-10-07). The frame format on the Jolla Phone is unverified until the Phase 1 spike |
| Storage format: KDBX4, one entry per account | Title = issuer, UserName = account, attribute `otp` = the `otpauth://totp/` URI exactly as KeePassXC writes it; `Password` stays empty. KeePassXC shows the same codes, which is criterion 4 |
| Secrets never cross the FFI | QML receives the code for the current step and the remaining seconds, never the seed. The seed is shown only on an explicit "show secret" or "show as QR" action (Phase 7), behind a confirmation |

Legacy attribute forms that KeePassXC reads (`Totp.h`, checked
2026-10-07): `TOTP Seed` with `TOTP Settings` (`step;digits` or
`step;S`), and KeePass 2's `TimeOtp-Secret-Base32`, `TimeOtp-Algorithm`,
`TimeOtp-Length`, `TimeOtp-Period`. SailFactor reads all of them and
writes only the `otp` URI, as KeePassXC does when it saves settings.

## 6. Unlock design

1. The master password (and optional key file) form the KDBX composite key.
2. The KDF from the file header runs in the Rust core on a worker thread,
   with progress in the UI.
3. On lock, key material, seeds and decoded entries are zeroized.

The rules decided for SailVault apply unchanged: never a PIN-wrapped key
on disk (an offline guess takes seconds), never a key in Sailfish Secrets
(its daemon derives the device-lock key from an empty lock code, and data
passes over D-Bus where it cannot be wiped).

An authenticator is opened many times a day, so the cost of the full
password is higher here than in a password manager. The answer is in
section 14 ("Unlock for daily use"), decided before Phase 3 ships.

Auto-lock defaults: 2 minutes idle in the foreground, 30 seconds in the
background, manual lock from the pulley menu and the cover. Shorter than
SailVault, since a code is read in seconds and the app is reopened often.

## 7. Data safety design

The phone holds the primary copy, so a writer bug can lock the user out
of every account. Inherited from SailVault's section 7, with one addition:

- Save atomically: temporary file, verify by re-reading and comparing the
  model, then rename
- Keep the last 3 versions as backups in the app's private data directory
  (`~/.local/share/de.tordenskjold/sailfactor/backups/`); delete them when
  the master password or key file changes
- Every edit pushes the previous state into entry history and updates
  `LastModificationTime`; deletes go to the recycle bin by default
- Hard deletes write `DeletedObjects`; moves set `LocationChanged`
- Write back the KDBX minor version that was read
- Addition: before an account is deleted, the UI shows the issuer and the
  account name again and uses a remorse timer, and the recycle bin is kept
  on by default, because a lost seed means a recovery through the service

Private storage from day one (SailVault needed a migration decision for
this): `databases/<name>.kdbx`, `keyfiles/<name>.key`, `backups/`. Files
from Documents or Downloads are added by unlocking them once and copied
in. `OrganizationName` and `ApplicationName` in the desktop file never
change after the first release, since they name the data directory.

## 8. Sync design

Copied from SailVault's design, with the parts that proved themselves on
the device (Nextcloud sync since 0.5.0):

- WebDAV over `QNetworkAccessManager`, only while the app runs: on open,
  after save, on pull-down
- Conditional requests: download with ETag, upload with `If-Match`
- If the remote file changed: download, merge (UUID, then
  `LastModificationTime`, history union, `LocationChanged`, apply
  `DeletedObjects`), save locally, upload
- Sync settings and the Nextcloud app password live in an entry of the
  database marked by entry CustomData, never in settings or Secrets
- Nextcloud Login Flow v2 by default, manual app password as a fallback
- TLS: system-trusted certificates, or a self-signed one pinned by its
  SHA-256 fingerprint after confirmation; never "ignore errors"
- Per-device confirmation of a sync configuration that arrived with the
  file (SailVault 0.5.2 review finding)
- Nextcloud returns 404, not 409, for a PUT into a missing folder; MKCOL
  first (SailVault finding)

Rule specific to an authenticator: the Nextcloud account used for sync
must not require a code stored in this file. The setup page says so and
recommends an app password. More generally, recovery after a lost phone
must work without any code from the file: the KDBX file on Nextcloud plus
KeePassXC on the PC.

## 9. Adding accounts

- QR scan: `Camera` with `VideoOutput` in QML; a `QAbstractVideoFilter`
  in C++ passes the luma plane of each frame to the core; the core runs
  `rqrr` and parses the `otpauth://` URI. Only `otpauth://totp/` is
  accepted; `otpauth-migration://` (Google Authenticator export) is Phase
  7; `hotp` is reported as unsupported
- Manual entry: issuer, account, Base32 secret; advanced: algorithm
  (SHA-1 default, SHA-256, SHA-512), digits (6 default, 1-10 as in
  KeePassXC), period (30 s default), Steam
- Every parsed URI is validated with bounds before it reaches the model:
  secret length, digits 1-10, period 1-3600 s, URI length, parameter count
- The first code is shown before the entry is saved, so the user can check
  it against the service's confirmation step

## 10. Harbour constraints

- Name prefix `harbour-`, everything except binary, desktop file and icons
  under `/usr/share/harbour-sailfactor`
- Only libraries and QML imports from the allowlist; the Rust core is
  statically linked
- Sailjail permissions, each with a reason: `Camera` (QR scan), `Internet`
  (Nextcloud sync, from Phase 5), `Documents` and `Downloads` (adding a
  file, saving a copy). Nothing else
- No daemons, systemd units or D-Bus services outside the app namespace
- Validator runs on every build, for aarch64 and armv7hl
- No "KeePass", "Google Authenticator" or other product names in the app
  name, icon or desktop file; the store text says the file format is
  KeePass-compatible

## 11. Phases

### Phase 0 - Scaffold

- Repository with `PLAN.md`, `CLAUDE.md` (rules from SailVault, adjusted;
  untracked, ignored by `.gitignore`), `LICENSE` (MIT), `.gitignore`,
  `harbour-sailfactor.pro`, `rpm/` spec and changes file, desktop file
  with the Sailjail section, icons, empty `core/` with `rust-version =
  "1.75"`, `.cargo/config.toml` for vendored sources and `aes_armv8`,
  `tools/` with the SailVault scripts that transfer (`measure-startup.sh`,
  `gen-third-party-licenses.py`, `gen-kdbx-fixtures.sh`)
- Build profile from SailVault's review: `panic = "abort"`, LTO, overflow
  checks on for the core package, `--locked --offline`, stripped binary,
  full RELRO
- `sfdk build` and `sfdk check` pass with a one-page app that shows the
  core version

Exit: an RPM that installs on the Jolla Phone and passes the validator.

### Phase 1 - Camera and QR spike

The one thing SailVault's experience does not cover.

- `Camera` and `VideoOutput` in QML inside the sandbox with the `Camera`
  permission
- A `QAbstractVideoFilter` that receives frames; record the pixel format
  and resolution the Jolla Phone delivers (unverified assumption: a YUV
  format whose first plane is luma); if frames are not mappable in the
  sandbox, fall back to `QCamera::capture` stills
- `rqrr` 0.10 in the core, called with the grayscale buffer; measure the
  time per frame on the device, decide how many frames per second to
  decode
- Validator passes with `QtMultimedia 5.6` and the `Camera` permission
- Results in `docs/spike-results.md`

Exit: a test QR code with an `otpauth://` URI is decoded on the device
within 2 s in daylight; the RPM passes the validator.

### Phase 2 - TOTP core and KDBX copy

- Copy the KDBX code, fixtures and fixture script from SailVault at a
  recorded commit; run its tests on the host; `tools/diff-sailvault-core.sh`
- `otpauth://` parser and writer, with KeePassXC's `writeSettings` format
  as the reference and the legacy attribute forms as readers
- TOTP generation: RFC 6238 appendix B vectors for SHA-1/256/512, RFC 4226
  appendix D for the HMAC truncation, Steam alphabet with a vector checked
  against KeePassXC
- Account model on top of the KDBX entry model: list, add, edit, delete,
  code for the current step and the remaining seconds
- C FFI with opaque handles: open, create, list, code for an entry, add
  from URI, add from fields, edit, delete, save, lock, decode QR buffer
- A fixture database with TOTP entries saved by the KeePassXC GUI (the
  steps go into `core/tests/fixtures/README.md`), so criterion 4 is tested
  against a file KeePassXC wrote, not one SailFactor wrote

Exit: all vectors pass; the KeePassXC fixture produces the same codes as
`keepassxc-cli show -t`.

### Phase 3 - MVP

- Create a file (Argon2id, levels as decided in section 14), unlock,
  auto-lock, cover with lock state and account count
- Account list with codes, countdown ring, copy with clipboard clear,
  search
- Add by QR scan and by manual entry; edit; delete with remorse and
  recycle bin
- Atomic save, verification, backups
- Threat model (`docs/threat-model.md`) before the first device test with
  real accounts
- Device test and measurements (criteria 2, 3, 6, 7)

Exit: usable as the daily authenticator on the Jolla Phone; codes verified
against KeePassXC and against a service's login.

### Phase 4 - Review and hardening

A security review of the Phase 3 state, with SailVault's review list as
the checklist, before any Phase 5 code. Then: add an existing file from
Documents or Downloads, key file support, save a copy, several files.

### Phase 5 - Merge and Nextcloud sync

Copied from SailVault 0.5.x: merge first, then sync, with the same tests
(conflicting edits, deletions, `keepassxc-cli merge` as the reference).
The sync entry, Login Flow v2, certificate pinning and the per-device
confirmation come over unchanged.

### Phase 6 - Harbour submission

Store texts, privacy policy, screenshots (1080 px wide; the Jolla Phone
renders 1032 px, upscale with Lanczos), both architectures built with
`-c no-fix-version` or from a clean tag; submit; fix QA findings before
growing the feature set.

### Phase 7 - After the first release

- Import: `otpauth-migration://` QR codes (Google Authenticator export,
  protobuf), entries with `otp` attributes from another KDBX file (move
  them out of a password manager), Aegis and andOTP JSON if demand shows
- Show an account as a QR code for moving it to another device
- Warning with a time estimate for slow KDF parameters
- Quick unlock as decided in section 14, if not already in Phase 3
- Translations (German first), cover actions
- Reproducible builds, signed releases

## 12. Security principles

- Seeds, key material and decoded entries live only in RAM, in the Rust
  core, and are zeroized on lock
- No plaintext secret is written to disk or to logs; no log files
- Crypto only through established crates; never hand-rolled primitives.
  Not every crate has a formal audit, and SailFactor has had no external
  review
- Untrusted input has strict bounds: KDBX files (KDF parameters, sizes,
  nesting depth, the limits SailVault settled on), `otpauth://` URIs, QR
  payloads, camera frames (dimensions), server responses
- Auto-lock on timeout; clipboard cleared after a timeout and on lock and
  exit
- Threat model written before Phase 3 ships

## 13. Lessons from SailVault, applied from the start

| Lesson (where it was found) | What SailFactor does from day one |
|-----------------------------|-----------------------------------|
| Timers stand still while the phone sleeps (review M1) | Lock, clipboard and countdown use `CLOCK_BOOTTIME`; the countdown is recomputed from the wall clock on every tick, never counted down |
| Cipher, MAC and KDF state freed without wiping (M2) | `zeroize` features on `aes`, `cbc`, `chacha20`, `twofish`; Argon2 through core-owned, zeroized memory |
| Overflow checks off in release (L6) | `overflow-checks = true` for the core package from Phase 0 |
| `cargo build` without `--locked` (L5) | `--locked --offline` in the qmake target |
| Partial RELRO, unstripped binary (L3, L4) | `-Wl,-z,relro,-z,now -s` in the `.pro` file from Phase 0 |
| Key file read with `readAll()` leaves copies (L8) | Read into a wiped buffer, size-checked first |
| Revealed values kept until the page is destroyed (L9) | A revealed secret is cleared when the page is left or the app goes to the background |
| Unsalted clipboard digest (L10) | Salted digest for "is the clipboard still ours" |
| Unlock finishing in the background skips the lock (L1) | Lock state is checked when the unlock task returns |
| `quintptr` is no Qt 5.6 metatype; a list bound its model to itself | FFI handles cross threads as `qulonglong`; model bindings reviewed on the first device test |
| Sync configuration travels with the file (0.5.2 review) | Per-device confirmation of a sync entry before it is used |
| Moving existing users is a migration | Private storage, stable `OrganizationName` and `ApplicationName`, file format and entry layout decided before the first release |
| `getrandom` 0.3 breaks `sfdk build`, host tests do not show it | `getrandom` 0.2; every dependency change checked with `sfdk build`, not only `cargo test` |
| Harbour wants armv7hl; the in-tree build leaves objects behind | Clean top-level objects before switching targets; both RPMs validated before submission |
| Pulley menus grow too long (0.5.1) | A settings page from the start; the pulley menu holds at most four items |
| Version suffixes fail the Harbour version check | Submit builds from a clean tag or with `-c no-fix-version` |
| Third-party notices drift after dependency changes | `gen-third-party-licenses.py --check` in the build |
| The entry page did not refresh after an edit (0.5.3) | Models emit changes from one place; the first device test edits and re-reads |

## 14. Open decisions

Open:

- **Unlock for daily use.** Options: (a) full master password every time,
  like SailVault; (b) opt-in quick unlock in RAM only, as SailVault's plan
  describes it for Phase 7: after a full unlock the derived key stays in
  the core while the app lives, a short PIN reopens, one wrong attempt, a
  time limit or quitting the app wipes the key. Proposal: ship (a) in
  Phase 3 and decide (b) after the first weeks of daily use; the
  measurement that matters is how often the app is actually quit by the
  system between uses. Never (c): anything on disk.
- **KDF level for a new file.** SailVault's Standard level (Argon2id, 256
  MiB, 3 iterations, about 1 s on the Jolla Phone) protects a file that
  is opened a few times a day. An authenticator is opened more often.
  Options: keep the same three levels with Standard as default, or add a
  lower "Daily" level at RFC 9106's second recommendation (64 MiB, 3
  iterations, about 0.25 s measured in SailVault's Phase 2). Proposal:
  keep SailVault's levels and default; the seed file deserves the same
  protection as the vault, and the quick unlock question above is the
  right place to buy convenience.
- **Clock warning.** TOTP fails silently with a wrong clock. Options: a
  note on the code list when the phone's clock is not set automatically
  (readable from `timed` only through D-Bus, probably not allowed), or a
  help text reachable from the list. Proposal: help text and a "my code is
  rejected" page in Phase 3; a clock check only if a Harbour-allowed way
  is found.
- **Steam codes in v1.** Cheap to generate (5 characters from KeePassXC's
  alphabet). Proposal: yes, in Phase 2, so a file with Steam entries
  behaves the same in both apps.

Decided:

- Name (2026-10-07): SailFactor, package `harbour-sailfactor`,
  `OrganizationName=de.tordenskjold`, `ApplicationName=sailfactor`.
  Known collision: a dormant GitHub hobby project from 2014 with the same
  name, never published in a store; accepted. A rename happens only if
  Harbour QA objects, which is before the first release and therefore
  before any data directory exists on a user's phone (a rename after the
  release would move `ApplicationName` and need a migration).
- Code sharing (2026-10-07): the KDBX code is copied from SailVault, not
  pulled in as a crate. The commit and file list of the copy are recorded
  here when Phase 2 does it; a fix in one app is ported by hand to the
  other. SailVault's `CLAUDE.md` gets a one-line note that fixes in
  `core/src/kdbx/` also apply to SailFactor (to be added in SailVault
  with the maintainer's approval).
- Storage format (2026-10-07): KDBX4 with KeePassXC's `otp` attribute as
  the only storage; no app-specific format.
- HOTP (2026-10-07): not supported, see section 4.
- Separation (2026-10-07): SailFactor never opens SailVault's file; a move
  of `otp` attributes from a vault is an import, Phase 7.
- Sync account (2026-10-07): the Nextcloud account for sync must not
  depend on a code in this file; the setup page says so.
- Unlock rules (2026-10-07): SailVault's rules, see section 6.
- Versioning (2026-10-07): Semantic Versioning as in SailVault; 0.1.0 is
  the first tagged build; 1.0.0 after the first Harbour round and outside
  feedback.
- License (2026-10-07): MIT; no code from GPL projects such as KeePassXC
  or QZXing, only documented behavior and RFC text.

## 15. References

- RFC 6238 (TOTP): https://www.rfc-editor.org/rfc/rfc6238
- RFC 4226 (HOTP, the HMAC truncation): https://www.rfc-editor.org/rfc/rfc4226
- Key URI format (`otpauth://`): https://github.com/google/google-authenticator/wiki/Key-Uri-Format
- KeePassXC TOTP source (`src/core/Totp.cpp`, `Totp.h`): https://github.com/keepassxreboot/keepassxc
- KDBX 4: https://keepass.info/help/kb/kdbx_4.html
- Harbour allowed APIs: https://docs.sailfishos.org/Develop/Apps/Harbour/Allowed_APIs/
- Harbour validator configuration (permissions, QML imports): https://github.com/sailfishos/sdk-harbour-rpmvalidator
- UI Definition of Done: https://docs.sailfishos.org/Develop/Apps/UI/Definition_of_Done/
- rqrr: https://github.com/WanzenBug/rqrr
- SailOTP (for comparison only, BSD-3): https://github.com/seiichiro0185/sailotp
- SailVault plan, reviews and spike results: `../SailVault/PLAN.md`, `../SailVault/docs/`
