# Security review, October 2026

Reviewed state: commit `98b5b3b` (release 0.1.0, end of Phase 3),
2026-10-08, before any Phase 4 feature work. Scope: `core/` (the TOTP and
`otpauth://` code, QR detection, the C API and the use of the KDBX code
copied from SailVault), `src/` (C++ bridge), `qml/`, build and packaging
configuration, dependency set.

Method: one review of the whole tree against SailVault's two reviews as the
checklist (their findings M1, M2, L1 to L13, I1 to I7, and the Harbour
review's M1 to M3, L1 to L11), the threat model and the Phase 4 list in the
plan, followed by two independent reviews of the same sources (Rust core
and C API; C++ bridge, QML and packaging). Every finding below was
re-checked against the code. Facts about the binary come from the 0.1.0
aarch64 RPM (`readelf`, `file`); Qt facts from the Qt 5.6 headers of the
SDK target; dependency advisories from a clone of the RustSec advisory
database of 2026-10-08 (`550efd3`); device facts from the Phase 3 device
test on the Jolla Phone (Sailfish OS 5.2.0.18, `docs/spike-results.md`).
Points that could not be checked are marked **unverified**.

The KDBX code (`core/src/kdbx/`, `secret.rs`, `random.rs`,
`argon2_memory.rs`) matches SailVault `8a9efff` byte for byte
(`tools/diff-sailvault-core.sh`), so SailVault's findings and fixes in it
apply unchanged; this review covers how SailToken uses it.

Result: no critical, high or medium findings, and no way to read the
file or a seed without the master password. The low findings are
hardening of the file layout, the lock during a save and the camera path,
a compatibility gap in reading unusual secrets, and two C API contract
points. All findings are fixed, except L9, which the device showed to be
no problem.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 9 |
| Info | 12 |

## Fix status (2026-10-08)

| Finding | Status | Commit |
|---------|--------|--------|
| L1 backups and directories | fixed: exclusive owner-only backups; data directory, `databases/` and `backups/` owner-only at creation, before every unlock and before every backup | `42b26a8` |
| L2 lock during a save | fixed: deadlines stopped, clipboard and pending account cleared, lists emptied at once; pending accounts need a readable database; a manual lock keeps its kind; the save starts before the lists reload | `65b82f6` |
| L3 frame copy bounds | fixed: the core's bound before any arithmetic, last byte within `mappedBytes()` | `11b70a0` |
| L4 skipped frame copy | fixed: wiped | `11b70a0` |
| L5 nested list reset | fixed: handle fetched before the reset | `4e11b3a` |
| L6 secrets with escapes | fixed: only `%3D` and `%20` decoded, anything else unreadable; four tests | `306da75` |
| L7 C API outputs | fixed: outputs cleared before any other check | `5e2d627` |
| L8 threading rule | fixed: stated in the header | `46a588a` |
| L9 remorse text | no change needed: Silica shows the issuer as plain text (verified on the device) | |
| I1 refused frame | fixed with L3 | `11b70a0` |
| I2 unused clipboard keeper | removed | `5654cbe` |
| I3 interrupted creation | no change needed | |
| I4 dependencies | no change needed | |
| I5 KeePassXC deviations | recorded in `PLAN.md` section 5 and the threat model | the docs commits of this review |
| I6 public settings fields | fixed: private with getters | `2744a44` |
| I7 quadratic listing | no change (copied code, outside the threat model) | |
| I8 late-unlock comment | fixed | `65b82f6` |
| I9 save before publishing | fixed | `65b82f6` |
| I10 overflow checks for parsers | not changed, see the finding | |
| I11 backup names | no change needed | |
| I12 changelog weekday | fixed | `b60db69` |

After the fixes: `cargo fmt`, `clippy -D warnings` and `cargo test` pass
on the host; `sfdk build` and `sfdk check` for aarch64 pass with 0
rpmlint errors; the rebuilt binary keeps PIE, `BIND_NOW`, `GNU_RELRO` and
is stripped. The fixed build passed the device tests below.

## SailVault's checklist applied to SailToken

| SailVault finding | SailToken |
|-------------------|------------|
| M1 timers during suspend | Deadlines on `CLOCK_BOOTTIME` in `AutoLock` and `ClipboardGuard`, checked before every access, on activation and by a 5 s watchdog; verified on the device in Phase 3 (lock after the display was off, clipboard cleared after 30 s) |
| M2 unwiped key material | The copied code with the `zeroize` features and core-owned Argon2 memory; HMAC and SHA states cannot be wiped, recorded in the threat model |
| L1 late unlock in background | `AutoLock::start` re-reads the application state |
| L2 quick-xml RUSTSEC-2026-0194 | Mitigated as in SailVault: `with_checks(false)`, 64 attributes per element; 0.41 needs Rust 1.79 |
| L3 partial RELRO, L4 symbol table | `FLAGS_1: NOW PIE`, `GNU_RELRO` segment, no `.symtab`, `file` reports "stripped" in the 0.1.0 RPM |
| L5 `--locked`, L6 overflow checks | `--offline --locked` in the `.pro` file; `overflow-checks` for the core package |
| L7 exit race | `~Authenticator` cancels, waits for the pool and delivers posted results; `~FrameScanner` waits for its own pool |
| L8 file read | `readBoundedFile`: regular files only, one exact allocation, POSIX reads |
| L9 revealed values on lock | No reveal in 0.1.0; the list reloads to empty and the account dialog loses its code when the pending account is dropped on lock; see L2 below for the lock during a save |
| L10 clipboard digest | No digest: the guard keeps the copied code itself, which is worthless after its time step |
| L11 small unwiped copies | Core strings that can hold a secret or a code are `Zeroizing` and sized up front; C++ keeps one owner per secret buffer and wipes it; Qt and QML strings cannot be wiped (threat model) |
| L12 pre-authentication bounds, L13 compatibility, I7 duplicate keys | In the copied code |
| I1 clipboard on exit | `QGuiApplication::sync()` after clearing |
| I2 keyboard input | `QEvent::InputMethod` resets the idle timer |
| I3 empty password | An empty field means no password, a failed attempt is retried with an empty password |
| I4 Send assertion | Compile-time `Send + Sync` assertion for all three handle types |
| I5 key file during unlock | No key files in 0.1.0 (Phase 4 feature work) |
| I6 unused dependencies | `argon2` without `password-hash`; `libQt5Network` is not linked (`readelf -d`) |
| Harbour M1 forbidden XML characters | Dropped when text enters the model (`layout.rs`, `replace_text`), carriage returns written as references; covers issuer and account names from QR codes |
| Harbour M2 clipboard after the field changed | Not applicable: the guard compares against the copied code itself |
| Harbour M3 growing buffers | `SecretBuffer` in the copied code; the QR payload writer and the URI writer never reallocate |
| Harbour L1, L2 attachments, nesting | In the copied code; SailToken adds entries to the root group only |
| Harbour L3, L4 backup rotation | Rotation matches exactly `<name>-<timestamp>.kdbx`; a file changed elsewhere is kept outside the rotation |
| Harbour L5 unlock page while unlocked | Returning to the unlock page locks; the path is fixed in 0.1.0 |
| Harbour L6 import kind | Not applicable (no import) |
| Harbour L7 key files, FIFOs | POSIX reads of regular files only |
| Harbour L8 unprotected OTP secrets shown | No attribute value is ever shown |
| Harbour L9 second save with the old digest | Edits are refused while a save runs; the result is applied before the next save can start |
| Harbour L10 shared password bytes | The task owns the only copy and wipes it |
| Harbour L11 dialog content after lock | The account dialog hides the code when the pending account is dropped; the rename dialog holds names only |
| Follow-up: merged file setting the sync target | Not applicable until Phase 5 |

## Low

### L1. Backups and the data directories were not owner-only from the start

`src/databasefile.cpp:114-134`, `src/databases.cpp:26-30,50-55`

The database file was created with mode 0600 through an exclusive POSIX
open, but a backup was written with `QFile` under the default umask and
made owner-only only after the write, through a path that would follow a
planted symlink. The directories `databases/` and the app's data directory
were created by `QDir::mkpath` with the default mode; `backups/` too.
On the Jolla Phone the data directory and `databases/` of the 0.1.0
installation were already owner-only, `backups/` was `drwxr-xr-x`; the
backups themselves were 0600. Sailjail keeps other sandboxed apps out of
the data directory, so the exposure is to unsandboxed same-user
processes, which can read anything anyway (threat model, attacker 3);
the finding is about the stated model ("owner-only permissions") holding
on every path. Fix: backups go through
the same exclusive, owner-only write as the database; the data directory,
`databases/` and `backups/` are made owner-only when a file is created,
before every unlock (so installations made by 0.1.0 are tightened) and
before every backup.

### L2. A lock requested during a save left the last codes on screen

`src/authenticator.cpp:241-291`, `src/accountlistmodel.cpp:143-196`

While a save ran, a lock (manual, idle or background) was only noted; the
state stayed `Unlocked`, the list kept the last codes until the save
finished (about 1 s at the Standard level, 5 s at Maximum), and an
automatic lock cleared neither the clipboard nor the pending account until
then. A scan or a typed secret still produced a pending account in that
window, and a manual lock after an idle expiry was reported as automatic.
Fix: `deferLock` stops the deadlines, clears the clipboard and the pending
account at once and empties the lists; pending accounts need a readable
database; a manual lock keeps its kind.

### L3. The frame copy trusted the frame's metadata

`src/framescanner.cpp:65-92`

`copyCentralLuma` read `height` rows of `bytesPerLine(0)` bytes from the
mapped frame on the strength of `width()`, `height()` and
`bytesPerLine()` alone, and computed `side * side` in `int` before
allocating the copy; the core's bound of 4096 pixels per side applied
only after the copy. Frame metadata that disagrees with the buffer, or a
side above 46340, would read past the mapping or overflow the allocation.
The camera stack is outside the attacker model, so this is robustness.
Fix: the core's bound (`ST_MAX_FRAME_DIMENSION`, new in the header) is
applied before any arithmetic, and the last byte of the last row must lie
within `mappedBytes()`; a buffer that reports no size is trusted as before
(whether the Jolla Phone's GL texture frames report one is
**unverified**).

### L4. A skipped frame copy was freed without wiping

`src/framescanner.cpp:193-198`

`FrameScanner::decode` returned early when a decode was already running
and let the copy, which shows the QR code, go out of scope unwiped. The
render thread is the only caller and checks `accepting()` first, so the
branch is not reached today. Fix: the copy is wiped on that path.

### L5. The list reload could nest inside itself

`src/accountlistmodel.cpp:143-179`

`reload` called `beginResetModel`, then asked the authenticator for the
handle, which checks the lock deadlines; a lock there reloads the list
again, nesting a second reset inside the first. Harmless with Qt's reset
signals as far as checked, but fragile. Fix: the handle is fetched before
the reset, so the nested reload runs on its own first.

### L6. Secrets with percent escapes were read differently than in KeePassXC

`core/src/otp/settings.rs:303-310,329,363-385`

Every `%XX` in a `secret` or KeeOtp `key` was decoded and the result
handed to the lenient Base32 reader. KeePassXC reads the value with
`QUrlQuery::queryItemValue` in its default mode, which keeps an escape
encoded when it stands for `+`, for a byte that is not UTF-8, or when the
`%` has no two hex digits; its Base32 reader then drops the `%` and keeps
the hex digits as symbols. Measured with `keepassxc-cli` 2.7.12:
`secret=JBSWY3DPEHPK3PXP%2B` gives SailToken the key `JBSWY3DPEHPK3PXP`
and KeePassXC `JBSWY3DPEHPK3PXP2B`, so each app shows a plausible but
different code for that entry, against criterion 2. No service issues such
a secret; the trigger is a hand-edited or garbled attribute. The lossy
UTF-8 conversion on that path could also reallocate and leave an unwiped
fragment. Fix: only the escapes KeePassXC itself writes, `%3D` and `%20`,
are decoded in a secret; any other escape makes the entry unreadable. The
four measured cases are tests now.

### L7. C API outputs stayed untouched when the handle was null

`core/src/ffi/accounts.rs`, `core/src/ffi/pending.rs`,
`core/src/ffi/database.rs`

The header promises that every output is null, empty or zero on an error,
but several entry points checked the handle and the output pointers in one
step and returned before writing the outputs, so a null handle left a
valid output pointer untouched (`st_account_code`, `st_account_rename`,
`st_account_delete`, `st_account_deletes_permanently`, `st_pending_text`,
`st_pending_code`, `st_database_open`, `st_database_save`, and the UUID
and kind outputs of the list). The bridge initializes every output before
the call, so nothing was affected; a caller relying on the promise would
have freed an uninitialized `StString`. Fix: outputs are validated and
cleared first, before any other check.

### L8. The header's threading rule was narrower than what the bridge does

`core/include/sailtoken_core.h:81-85`

"A handle is used by one thread at a time", while the bridge runs
`st_database_save` on a pool thread and keeps listing accounts and
computing codes on the main thread with the same handle. This is sound:
the handle types are asserted `Send + Sync`, `save` takes `&self`, there
is no `unsafe` outside `ffi/` to hide interior mutability, and every
mutating call is refused while a save runs. Fix: the header states the
real rule, concurrent readers through a const handle, exclusive access for
mutable handles and `st_database_free`.

### L9. The remorse text shows an issuer through a Silica-internal label (unverified)

`qml/pages/AccountListPage.qml:28-36`, `qml/harbour-sailtoken.qml:18-21`

Every app-owned label that shows an issuer or account name is plain text.
The remorse text "Deleting %1 permanently" goes to Silica's
`RemorsePopup`, whose label the app does not control; plain rendering there
rests on the window's `_defaultLabelFormat`, set only when the property
exists. An issuer from a QR code (threat model, attacker 5) with markup
could then recolor or hide part of the countdown's text. The property and
`RemorsePopup`'s label could not be checked without the Silica sources.
Verified on the device: an account with the issuer `<b>bold</b>` shows
the issuer with its angle brackets, in the list and in the remorse text.
No change.

## Info

- I1. A frame the core refused (`ST_INVALID_ARGUMENT`, only for more
  than 4096 pixels per side) was reported as "holds no two-factor
  account"; it is reported as unsupported frames now (with L3).
- I2. `ClipboardGuard::keepCopiedValue`, SailVault's fix for a clipboard
  value whose source changes, had no caller: the guard here holds the
  copied code itself. Removed.
- I3. Quitting during the key derivation of a new file, after the file
  was written, leaves `hasFile` false until the next start; the next
  creation then reports "already exists". Not reachable from the UI (the
  unlock page and the cover offer no lock while creating); recomputed at
  start. No change.
- I4. Dependencies: see "Checked and found correct"; `lru` 0.16.4
  (RUSTSEC-2026-0253) does not apply with `panic = "abort"` and no
  `catch_unwind`; `quick-xml` stays mitigated as in SailVault. No change.
- I5. Deviations from KeePassXC beyond the two the plan listed, measured
  with `keepassxc-cli` 2.7.12 on a probe file of 50 entries:
  `TimeOtp-Length` above 10 (KeePassXC computes a 12-digit code,
  SailToken shows the entry as unreadable), a URI without a secret or
  with an empty one (KeePassXC computes a code from the empty key), and
  `TOTP Settings` without a seed or an `otp` value in neither form
  (KeePassXC shows no TOTP, SailToken an unreadable entry). Recorded in
  `PLAN.md` section 5 and the threat model; SailToken's behavior is kept.
- I6. `TotpSettings` exposed `digits` and `period` as public fields; safe
  code inside the crate could have set a period of zero after
  construction and made `code_at` abort. Not reachable through the C API.
  The fields are private with getters now.
- I7. Listing and the per-second code lookup walk the entry tree per
  account (`accounts::list` calls `in_recycle_bin` for each entry), so a
  file with tens of thousands of entries would make the list slow (not
  measured). The user opened that file with their own password, so it is
  outside the threat model; the tree walk is in the copied KDBX code. No
  change.
- I8. The comment at `m_autoLock.start()` claimed an immediate lock after
  a background stay longer than the deadline during the KDF; the deadline
  starts at the unlock, as in SailVault. Comment corrected.
- I9. `change()` published an edit to the lists before starting the save,
  so a lock deadline met inside the reload would have discarded the edit
  instead of waiting for the save. Not reachable (every edit follows input
  by seconds), but the save starts first now.
- I10. `overflow-checks` cover the core package only; `rqrr`, `quick-xml`,
  `base64` and `flate2` wrap in release. In safe Rust a wrap cannot corrupt
  memory, only give a wrong result or a panic (which aborts). Turning the
  checks on for the parsers would abort on arithmetic that wraps by design
  in paths the tests do not reach, so this is not changed.
- I11. Backups are named by wall-clock time; a save after the clock was
  set back sorts as the oldest backup and rotates out first. The current
  file is unaffected. No change.
- I12. The 0.1.0 changelog entry named a wrong weekday ("Wed Oct 08
  2026"), which `rpmbuild` reports as a bogus date. Corrected.

Unverified: whether `QVideoFrame::mappedBytes()` reports a size for the
Jolla Phone's GL texture frames (L3; scanning works either way, so the
check either applies or is skipped); whether Qt 5.6's
`QDeclarativeVideoOutput` deletes a filter runnable with the item or at
the next sync (either way it is not run after the item is gone);
KeePassXC's GUI uses the same code paths as `keepassxc-cli` for TOTP (L6,
I5).

## Checked and found correct

- Seeds stay in the core: the C API hands out issuers, account names,
  the code for one time step and the seconds left (`st_account_code`,
  `st_pending_code`, `st_account_list_text`, `st_pending_text`); every
  string crossing it is wiped by `st_string_free`; `TotpSettings` leaves
  the secret out of its `Debug` output; `StPending` has none. A typed
  secret crosses once, as UTF-8 bytes wiped by `CoreText`.
- Bounds on untrusted input: URIs and attribute values 2048 bytes, 32
  query items, decoded secret at most 512 bytes, digits 1 to 10, period 1
  to 86400 (`otp/settings.rs`, `otp/base32.rs`); frames 1 to 4096 pixels
  per side, pixel step 1 to 4, row stride checked against the buffer with
  checked arithmetic (`qr.rs`, `LumaFrame::new`); QR payloads 2048 bytes
  in a buffer that never reallocates; the decoder subsamples frames above
  1280 pixels. Tests cover each bound (`core/tests/otp.rs`,
  `core/tests/qr.rs`).
- No panic reachable from input: the one `expect` in
  `st_pending_from_frame` follows the decoder's own UTF-8 check; HMAC
  accepts keys of any length; `10u64.pow(digits)` with digits at most 10;
  the truncation offset indexes within the shortest digest (SHA-1, 20
  bytes, offset at most 15 plus 3); `split_label` slices at ASCII
  positions only; `overflow-checks` are on for the core package.
- Codes: RFC 6238 and RFC 4226 vectors for SHA-1, SHA-256 and SHA-512,
  the Steam alphabet least significant character first, the period
  boundary and leading zeros are pinned by tests; the KeePassXC fixture
  made with `keepassxc-cli` shows the same codes for every attribute form
  (`core/tests/totp_keepassxc.rs`). The core review added a probe file of
  50 edge cases (form precedence, empty first forms, KeeOtp with lower
  case names, legacy `step;S`, clamping of digits and period, Steam with
  explicit settings, algorithm spellings, duplicate `secret`, fragments,
  upper-case scheme, lenient Base32) read by both apps: all match except
  the deviations recorded in I5 and L6. Countdowns are recomputed from
  the wall clock at every tick and never counted down; the list ticks only
  in the foreground.
- Frames: a smoke test of 528 frames through `st_pending_from_frame`
  (1 x 1 to 4096 x 4096, noise, checkerboards, random stride and step)
  returned only `ST_NOT_FOUND`; one byte short, a side of 4097, a step of
  0 or 5, a short stride and `u32::MAX` dimensions were refused with
  `ST_INVALID_ARGUMENT`. `rqrr` has no `unsafe` and maps writer errors
  without unwrapping; it has not been fuzzed (threat model).
- HOTP and foreign entries: `rename` writes Title and UserName through
  `update_entry`, `delete` moves the entry; no attribute is rewritten, so
  a HOTP entry or a KeePassXC password entry survives a save unchanged.
  Every entry outside the recycle bin is listed with what it can show.
- C API: every entry point checks its pointers, writes null, empty or
  zero outputs first and assigns on success only; `unsafe` only in
  `core/src/ffi/`; handles are freed once by `unique_ptr` owners in the
  bridge; `StDatabase`, `StPending` and `StAccountList` are asserted
  `Send + Sync` at compile time, which is what a save on a pool thread
  while the main thread reads the same handle needs.
- Bridge: the attempt counter drops stale unlock and save results; a lock
  during an unlock frees the late handle; edits are refused while a save
  runs; the password bytes have one owner and are wiped in the task; the
  frame copy has one owner and is wiped after the decode; the scanner's
  own pool is drained before it is destroyed and a posted result is
  delivered so its account is freed.
- Files: regular files only, read into one exact allocation; the
  temporary file is created with `O_EXCL | O_NOFOLLOW` after removing a
  leftover, written, synced, read back through the same descriptor and
  renamed; the directory is synced; a new file is linked into place and
  fails if a file appeared meanwhile; the file keeps its mode (0600 from
  creation); the backup rotation matches only this database's backups and
  keeps a version changed elsewhere outside the rotation.
- Deadlines: `CLOCK_BOOTTIME` stamps for idle, background and clipboard,
  checked before every database access, on activation and by 5 s
  watchdogs; a late unlock re-reads the application state; the clipboard
  is cleared only while it still holds the copied code, on the deadline,
  on lock and on exit with a flush; typing on the keyboard counts as
  activity.
- QML: every visible string goes through `qsTr()`; issuers and account
  names are shown through `Text.PlainText` labels and the window sets
  Silica's default label format to plain text when the property exists
  (whether `RemorsePopup` and `Notices` honour it is **unverified**, as
  in SailVault); the cover shows the lock state and the account count;
  codes leave the list and the account dialog on lock; returning to the
  unlock page locks; dialogs refuse to accept while a save runs; pages are
  loaded with `Qt.resolvedUrl`.
- Build and packaging (0.1.0 aarch64 RPM): PIE, `FLAGS_1: NOW PIE`, a
  `GNU_RELRO` segment, non-executable stack, stack protector and fortified
  calls present, stripped; links `libsailfishapp`, Qt Multimedia, Quick,
  Gui, Qml and Core only; QML imports `QtQuick 2.0`, `QtMultimedia 5.6`,
  `Sailfish.Silica 1.0` and the app's own module; Sailjail permission
  `Camera` only; the RPM holds the binary, the desktop file, icons and
  `/usr/share/harbour-sailtoken/qml`; `cargo build --release --offline
  --locked` with an explicit triple, `panic = "abort"`, LTO,
  `overflow-checks` for the core package; the five vendored `build.rs`
  scripts (`crc32fast`, `generic-array`, `libc`, `proc-macro2`, `quote`)
  are compiler probes; no product name in the app name, icon or desktop
  file. The validator passes with 0 rpmlint errors.
- Dependencies against the RustSec database of 2026-10-08: every
  advisory for a locked crate is patched in the locked version, except
  RUSTSEC-2026-0194 and 0195 (`quick-xml`, mitigated as in SailVault) and
  RUSTSEC-2026-0253 (`lru` 0.16.4 through `rqrr`: `LruCache::pop` is not
  panic-safe, exploitable only with unwinding and `catch_unwind`; the
  core aborts on panic and never catches, so it does not apply; 0.18.2
  would be the fix, its MSRV **unverified**).
- No secret, code, password or file content in any log line, `qDebug`,
  error text, notice or test output; the only `printf` is the startup
  timestamp behind `--startup-trace`.

## Device test (2026-10-08)

Jolla Phone (2026), Sailfish OS 5.2.0.18, the build of `b60db69`
installed over 0.1.0 with its test file, made-up accounts only.

Verified on the device:

- Scanning a new test code from a computer screen: found at once, with
  issuer, account name and first code in the dialog (L3).
- Permissions before and after the first save of the fixed build, read
  with `ls -la` over `sfdk device exec` (L1):

  | Path | 0.1.0 | Fixed build |
  |------|-------|-------------|
  | Data directory, `databases/` | `drwx------` | `drwx------` |
  | `backups/` | `drwxr-xr-x` | `drwx------` |
  | File and backups | `-rw-------` | `-rw-------` |

  The rotation keeps three backups as before.
- Locking from the pulley menu right after a rename, while the save ran:
  the list emptied at once and the unlock page followed (L2).
- An issuer `<b>bold</b>` shows with its angle brackets in the list and
  in the remorse text (L9).
- Regression: renaming and deleting work; the idle lock works; after
  30 seconds in the background the app is locked and the unlock page says
  "Locked automatically"; a copied code pastes in another app and is gone
  from the clipboard after 30 seconds.
