# SailFactor threat model

Status: 2026-10-08, Phase 5 (the app keeps one file, creates it or adds
it from Documents or Downloads with an optional key file, saves a copy
there, deletes it while unlocked, merges another copy, syncs it with
Nextcloud, shows codes, adds accounts by QR scan or by typing the secret,
renames and deletes them). Written before the first device test
with real accounts, brought up to date with the Phase 4 security review
(`security-review-2026-10.md`) and the file features after it. Covers
the code in this repository at that state. Points marked
**unverified** have not been checked on Sailfish OS or the device yet;
points marked "checked for SailVault" were measured on the same Jolla Phone
(Sailfish OS 5.2.0.18) for SailVault, which shares this design.

## What the separation protects

SailFactor keeps the second factor of logins in its own encrypted file with
its own master password, apart from the password manager. If the password
manager's file or its master password leaks, the codes stay safe. This only
holds when the two master passwords differ; the app says so when a file is
created.

The separation does not protect against a compromised phone: it holds both
apps, and whoever controls it can wait for both to be unlocked.

## Assets

| Asset | Where it lives |
|-------|----------------|
| TOTP secrets (seeds) | Encrypted in the KDBX file; decrypted only in RAM, in the Rust core, while unlocked |
| An account waiting to be added | In the core, from a scan or a typed secret until it is added or dropped; dropped on lock |
| Codes | Computed in the core; on screen while the list shows; on the clipboard for up to 30 seconds after a copy |
| Master password | Typed into the unlock page; never stored |
| The file | `~/.local/share/de.tordenskjold/sailfactor/databases/SailFactor.kdbx`, owner-only permissions |
| Key file | `~/.local/share/de.tordenskjold/sailfactor/keyfiles/SailFactor.key`, unencrypted, owner-only permissions, only for a file added with one; read into RAM during an unlock |
| Copies the user saves, originals not yet deleted, copies merged in | Documents or Downloads, encrypted like the file; key files unencrypted |
| ETag and file digest of the last sync, digest of the confirmed sync configuration | `~/.config/de.tordenskjold/sailfactor/settings.ini` (no secrets); dropped when the file is deleted |
| Nextcloud app password, server, login name, path, pinned certificate | An entry of the file, encrypted like every entry and not shown in the account list; in RAM while a sync runs, also in Qt buffers that cannot be wiped |
| Copy of the file on Nextcloud | The user's Nextcloud, encrypted like the file |
| Backups | `~/.local/share/de.tordenskjold/sailfactor/backups/`: the three newest versions the app replaced, encrypted like the file, owner-only like the file |
| Camera frames | While the scan page is open: the camera stack's buffers, and one copy of the brightness per decoded frame |

## Architecture and trust boundaries

```
QML / JavaScript engine   issuers, account names, current codes
        |
C++ bridge (Qt 5.6)       file reading and writing, backups, clipboard, lock state,
        |                 timers, camera frames
        |  C API (core/include/sailfactor_core.h)
Rust core                 KDBX4 parsing and writing, KDF, encryption, TOTP,
                          otpauth URIs, QR decoding
```

- The Rust core holds the decrypted file and the secrets. The KDBX code is
  SailVault's (copied, see `PLAN.md` section 5), with the same bounds on
  untrusted files: header size, KDF parameters, payload (256 MiB),
  decompressed XML (512 MiB), XML depth (128) and attributes per element
  (64). Decrypted buffers, cipher states and the Argon2 working memory are
  zeroized when dropped.
- Seeds never cross the C API. The bridge gets issuers, account names, the
  code for the current time step and the seconds left. A typed secret
  crosses once, on the way in.
- A QR code is decoded in the core from a copy of the frame's brightness,
  and its payload is parsed there; it never reaches C++ or QML. The copy
  is bounded by the frame's dimensions and its mapped size, and wiped
  after the decode.
- `otpauth://` URIs and the TOTP attributes of an entry are untrusted input
  with bounds: 2048 bytes per URI or attribute, 32 query parameters, a
  secret of at most 512 bytes, digits 1 to 10, a period of 1 to 86400
  seconds. Camera frames are bounded to 4096 pixels per side, QR payloads
  to 2048 bytes.
- The app runs in the Sailjail sandbox with the permissions `Camera`, used
  only on the scan page, and `Documents` and `Downloads`, used only to read
  a file and key file the user picks, to save a copy under a name the user
  gives, and to delete the originals of an added file or a merged copy when
  asked; and `Internet`, used only by the Nextcloud sync.

## Attackers and protections

### 1. Lost or stolen phone, app locked or not running

Protected:

- The file is encrypted with the master password through the KDF stored in
  the file. New files use Argon2id with 256 MiB and 3 iterations or more,
  and a master password of at least 15 characters. Nothing that unlocks
  the file is stored on the device: no PIN-wrapped key, no key in Sailfish
  Secrets.
- No decrypted data is written to disk. A save writes the encrypted file to
  a new temporary file next to it (created exclusively, never through a
  symlink, read back through the same descriptor) and renames it over the
  original; the previous file goes to the backups, encrypted as it was and
  written the same way. The app's data directory and the directories for
  files and backups are owner-only.
- `/home` is LUKS-encrypted on the Jolla Phone (checked for SailVault),
  which protects the files while the phone is off.

Limits:

- The protection is only as strong as the master password and the KDF
  parameters. For a file added from KeePassXC the user chose them there,
  and the app opens weak settings without warning; a KDBX 3.1 file is
  stored as KDBX 4 with Argon2id at the level chosen when it is added.
- A key file kept on the phone next to the file adds no protection against
  someone who has the phone's files; it protects a copy that leaves the
  phone without it. For that reason the app adds only files that need a
  password, so the files on the phone never unlock the file by
  themselves.
- Backups are protected by the password in effect when they were written;
  re-protecting or deleting them on a password change is planned
  (`PLAN.md`, section 7).

### 2. Unlocked phone in someone else's hands

Protected:

- Auto-lock after 2 minutes without input and after 30 seconds in the
  background; manual lock from the pulley menu and the cover. Locking drops
  and zeroizes the decrypted file and any account waiting to be added. A
  lock requested while a save still reads the file clears the clipboard and
  the waiting account at once, hides the accounts, and releases the file
  when the save ends, within the time one key derivation takes.
- The deadlines count time the phone spends asleep (`CLOCK_BOOTTIME`). They
  are checked before every access, when the app becomes active, and every
  5 seconds while a deadline is pending (as in SailVault, whose behavior
  after sleep was checked on the device).
- The cover shows the lock state and the number of accounts, never a code.
- Codes are recomputed from the wall clock each second while the list is
  in the foreground, and not at all in the background.
- Swiping back to the unlock page locks the file.
- Deleting the file, with its key file and backups, is offered only while
  the app is unlocked, behind a confirmation, so the master password is
  needed to remove the accounts.

Limits:

- Within the lock window, every code is visible and can be copied. The
  secrets themselves are not shown anywhere in the app.
- Locking on device lock would need a system D-Bus service the sandbox does
  not allow; the background rule locks 30 seconds after the display turns
  off, or within 5 seconds of waking up if the phone slept longer.

### 3. Other apps on the same phone

Protected:

- Sailjail isolates the app's memory and private directories from other
  sandboxed apps; the file, its key file and backups live there, so apps with
  the `Documents` or `Downloads` permission can neither read nor replace
  nor delete them. A file from outside is added by unlocking it once; only
  then are the file and the key file that opened it copied in, and the
  app offers to delete the originals.
- A copied code is cleared from the clipboard 30 seconds after the copy
  (counting sleep time), on lock and on exit, but only if the clipboard
  still holds that code, so the app never clears what another app put
  there. Clearing from the background and on exit was checked for
  SailVault.
- The camera is active only while the scan page is shown and the app is in
  the foreground.

Limits:

- During the 30 seconds, any app that can read the clipboard can read the
  copied code. A code is useful only within its time step, usually 30
  seconds, and only together with the password of that account.
- A copy saved to Documents or Downloads, and an original not yet
  deleted, can be read, replaced and deleted by every app with that
  permission. The file is encrypted, a key file next to it is not; the
  dialog says so and suggests deleting the copy once it is on the
  computer.
- Unsandboxed apps (OpenRepos, Chum, `Sandboxing=Disabled`) and the user
  with `devel-su` are not restricted by Sailjail.

### 4. Crafted file

Protected:

- The header SHA-256 and HMAC and the per-block HMAC are checked before any
  decrypted data is used, so a modified file is rejected unless the
  attacker knows the master password.
- Parsing is done in Rust with the bounds above; malformed input produces
  an error, not undefined behavior. `unsafe` code is limited to the C API.
- TOTP settings an entry cannot express are shown as unreadable instead of
  producing codes: more than ten digits, an empty secret, or a secret with
  a percent escape that KeePassXC would read as a different key. A
  counter-based (HOTP) entry is shown as not supported instead of with
  wrong codes.

Limits:

- A file the attacker created with their own master password opens
  normally if the user knows it; the app cannot tell whose file it is.

### 5. Crafted QR code

Protected:

- The decoder runs in the core on a bounded frame and stops at a payload of
  2048 bytes. Only `otpauth://totp/` URIs become accounts; anything else is
  reported and nothing is stored.
- A scanned account is shown with its issuer, account name and first code
  before it is added, and the user can correct the names.

Limits:

- A code that sets misleading issuer or account names is shown with those
  names until the user corrects them.
- The QR decoder (`rqrr`) is pure Rust but has not been fuzzed for this
  app. Because the core is built with `panic = "abort"`, a crafted code
  that made it panic would end the app; it could not corrupt memory.

### 6. Network attacker and the Nextcloud server

The sync is SailVault's (`src/nextcloud.*`, `src/sync.*`), whose behavior
toward the server was checked on the device for SailVault 0.5.x.

Protected:

- Requests go over https only, through Qt and OpenSSL with the certificates
  the system trusts. A self-signed certificate is accepted only after the
  user confirmed its SHA-256 fingerprint, and then only exactly that
  certificate, for the errors a self-signed certificate raises; a changed
  pinned certificate stops the sync with a warning. Certificate errors are
  never ignored otherwise.
- Redirects are not followed, since Qt 5.6 would send the credentials to
  any redirect target; cookies are not kept.
- The app password is sent as Basic auth on each request and never logged.
  The Login Flow v2 poll token, which yields the app password, goes only to
  the server the user entered, and the flow is refused if the server
  points its poll or login address elsewhere.
- A sync configuration runs only once it is confirmed on this device: the
  settings keep a SHA-256 digest of server, login name, path and pinned
  certificate (not the password). Setting sync up on the phone confirms it;
  a configuration that arrived any other way, such as in a file added from
  another device, sends nothing until the user accepted a dialog showing
  the server. Entries merged from a file unlocked with other credentials
  lose the sync marker, so such a file cannot redirect the sync.
- Nextcloud only receives the encrypted KDBX file. A downloaded file is
  untrusted input with the reader's bounds, and it is merged only if it
  opens with the credentials of the open file. An older file served again
  merges without removing newer changes.
- What the last sync knew (ETag, digest, confirmation) is dropped when the
  file is deleted, so a file added afterwards is merged with the copy on
  Nextcloud before anything is uploaded, never uploaded over it.
- The setup page asks for a Nextcloud login that does not need a code from
  this file, and recommends an app password: after a lost phone, the copy
  on Nextcloud and KeePassXC on a computer are the way back to the codes.
- The sync entry, "Nextcloud sync (SailFactor)", carries its own marker, so
  a SailVault sync entry in a file merged or added here is never taken for
  SailFactor's configuration, and the other way round.

Limits:

- A Nextcloud app password opens all files of the account, not only this
  file. Anyone who can open the file sees it in the sync entry, also in
  copies on the computer and on the server; it can be revoked in
  Nextcloud.
- The server, its admin or anyone who breaks into it gets the encrypted
  file and can guess master passwords offline; the KDF parameters decide
  the cost. File size and sync times are visible to the server.
- A user who confirms a wrong fingerprint lets an attacker in the middle
  read the app password and the encrypted file.
- The app password exists in Qt buffers during a sync and cannot be wiped
  there, like other Qt strings.
- Deletions from the other copy are applied when the item did not change
  afterwards; a server that serves a file with forged deletion records
  could only do so with the credentials of the file.

## Known limits of the implementation

- **QML and Qt strings cannot be wiped.** The master password and a typed
  secret exist as `QString` in Qt and the JavaScript engine and are freed
  without zeroing, as are issuers, account names and the codes on screen.
  The keyboard sees what is typed; the password and secret fields disable
  prediction and automatic capitalization.
- **C++ buffers are wiped on a best-effort basis.** The password bytes and
  the copy of a camera frame have a single owner and are overwritten with
  `explicit_bzero` after use. Qt's implicit sharing elsewhere can leave
  copies that are freed without zeroing.
- **Camera buffers.** The camera stack's own frame buffers, which show the
  QR code and its secret, are outside the app's control.
- **Decoder buffers are not wiped.** `rqrr` keeps the decoded bits of a QR
  code in internal buffers that are freed without zeroing; the payload
  itself is collected in a zeroized buffer.
- **HMAC and SHA-2 states are not wiped.** The `hmac`, `sha1` and `sha2`
  crates offer no zeroize support; their internal states, derived from the
  seed when a code is computed, are freed without zeroing.
- **Compression buffers are not wiped.** `flate2` keeps part of the
  plaintext in internal buffers that are freed without zeroing.
- **Copies by the compiler.** The compiler may leave copies of secrets in
  registers or stack slots that are not wiped.
- **Memory paging.** The phone swaps to zram (compressed RAM, checked for
  SailVault), not to flash. The app does not lock its memory.
- **Crash dumps.** `kernel.core_pattern` is `|/bin/false` on the Jolla Phone
  (checked for SailVault), so core dumps are discarded.
- **Screen content.** Codes are visible on screen and in screenshots the
  user takes. Whether the app switcher keeps a snapshot of the list is
  **unverified**.
- **The clock.** Codes depend on the phone's time. A wrong clock gives codes
  that services reject; the app cannot check the clock and explains this on
  its help page.
- **Old values stay in the file.** As in KeePassXC, a rename keeps the
  previous names as a history item, and a deleted account sits in the
  recycle bin, with its secret, until it is deleted there. Backups keep
  earlier versions until they rotate out.

## Out of scope

- An attacker with root on the phone, a compromised OS, keyboard or camera
  stack, or hardware attacks on RAM.
- The security of KeePassXC and of other devices that open the same file.
- Phishing: a code entered on a fake site is as useful to the attacker as
  on the real one, within its time step.

## Changes in later phases

- A quick unlock (Phase 7 at the earliest, opt-in, RAM only) would add a
  section here.

## Reporting

See [SECURITY.md](../SECURITY.md): a private report on GitHub.
