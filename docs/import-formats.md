# Import formats

The formats of the first import release (`PLAN.md` section 14, decided
2026-10-10; a plain text file of `otpauth://` URIs was dropped the same
day, since it carries every secret unencrypted between devices), as documented by their authors or by permissively licensed
descriptions. SailToken follows these descriptions and copies no code:
Aegis is GPL-3.0, and Google publishes no specification for its export.

Every format is untrusted input. Each reader has hard limits, rejects
anything outside them with an error, and keeps seeds in zeroized memory
from the moment they are decoded. Every reader is tested with exports
made in the real app with made-up accounts (fixtures still to be made by
the maintainer).

## What an import does with an entry

| Entry | Result |
|-------|--------|
| TOTP with SHA1, SHA256 or SHA512 | added as an account |
| Steam | added as a Steam account (supported since Phase 2) |
| HOTP | skipped and counted: SailToken refuses new HOTP accounts (`PLAN.md` section 4) |
| MD5, mOTP, Yandex or any other type | skipped and counted as not supported |
| Same secret, issuer and account as an existing account | marked as a duplicate, not selected by default |

The user sees all entries before anything is written, chooses which to
add, and the file is saved once, with the usual verified write and
backups.

## 1. Google Authenticator export QR codes (the main way)

Source: the field numbers in `migration.proto` of
[dim13/otpauth](https://github.com/dim13/otpauth/blob/master/migration/migration.proto)
(ISC license), a description derived from the app's output. There is no
official specification, so the format may change without notice.

The old phone shows the codes and SailToken scans them from its screen,
so no file with the secrets leaves the old phone. Google Authenticator
blocks screenshots of its export (reported in migration guides, e.g.
2FAuth's), and splits an export of more than 10 accounts into several
codes of 10 each.

URI: `otpauth-migration://offline?data=<payload>`, where the payload is
standard Base64 (with `+`, `/` and padding), percent-encoded in the URI.
The decoded bytes are a protobuf message:

```
Payload
  1  OtpParameters   repeated
  2  version         int32
  3  batch_size      int32
  4  batch_index     int32
  5  batch_id        int32

OtpParameters
  1  secret     bytes   (raw, not Base32)
  2  name       string
  3  issuer     string
  4  algorithm  enum    0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
  5  digits     enum    0 unspecified, 1 six, 2 eight
  6  type       enum    0 unspecified, 1 HOTP, 2 TOTP
  7  counter    uint64
  8  unique_id  string
```

- The format carries no period; every TOTP entry uses 30 seconds.
  Unspecified type, algorithm and digits mean TOTP, SHA1 and six, as
  the app assumes. Padding of the Base64 is optional.
- `name` often repeats the issuer as `Issuer:account`, the label of the
  URI the account came from. The prefix is dropped when it equals the
  issuer, and becomes the issuer when the issuer field is empty; any
  other name is kept whole.
- A message that breaks the wire format spoils the whole code; a value
  SailToken cannot use (HOTP, MD5, an unknown type or length, an empty
  or oversized secret, a name that is not UTF-8) skips only its account.
- An export with many accounts is split over several QR codes with the
  same `batch_id`, `batch_index` from 0 and `batch_size`. The core
  collects the codes of one batch in any order (`MigrationBatch`),
  ignores repeats and refuses a code from another batch; the scan page
  shows "2 of 3 scanned" and offers the import when all are in. Skipped
  entries are numbered across the codes in batch order.
- A small hand-written protobuf reader (`core/src/import/protobuf.rs`)
  reads varints and length-delimited fields and skips fixed-width and
  unknown fields, each length checked against the remaining bytes;
  group wire types and varints beyond 64 bits are refused.
- Limits: payload at most 4096 bytes decoded (`MAX_MIGRATION_PAYLOAD`;
  a QR code holds at most 2953 bytes), at most 100 accounts per code,
  batch size at most 50 (`MAX_BATCH_SIZE`), secret at most 512 bytes
  (`MAX_SECRET_LENGTH`, as for every account), names at most 1024
  bytes. The scanner accepts payloads up to 4096 bytes
  (`qr::MAX_PAYLOAD_LENGTH`), above the 2953 bytes of a QR code in byte
  mode, so a full export code fits.

Device test (2026-10-10, Jolla Phone): 12 made-up accounts scanned into
Google Authenticator, exported as two codes and imported in SailToken,
all of them; an account scanned with `period=60` changes every 30
seconds after the import, as the format carries no time step. Aegis can
show its accounts as codes in this format too ("transfer"); its export
of the same 12 accounts left out the one with eight digits and the one
with SHA256, so the vault file below is the complete way for Aegis.

## 2. Aegis vault files

Source:
[docs/vault.md](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
in the Aegis repository. The document states no license; it is used as
a description only.

A UTF-8 JSON object: `version` (1), `header` and `db`.

- **Plain export:** `header.slots` and `header.params` are null; `db` is
  the content object below.
- **Encrypted export:**
  - `header.params` holds `nonce` and `tag` (hex) of the AES-256-GCM
    encryption of `db`; `db` is the Base64 ciphertext (with padding).
  - `header.slots` lists wrapped copies of the 256-bit master key. Only
    password slots (`type` 1) can be opened here; raw (0) and biometric
    (2) slots are skipped. A password slot holds `salt` (hex, 256 bits),
    scrypt parameters `n`, `r`, `p` (Aegis uses 2^15, 8, 1), the wrapped
    `key` (hex) and `key_params` with `nonce` and `tag` (hex).
  - Opening: scrypt(password, salt, n, r, p) gives a 32-byte key that
    decrypts `key` with AES-256-GCM to the master key; the master key
    decrypts `db`. A wrong password fails the GCM tag check. Each
    password slot is tried in turn.
- **Content:** `version` (3), `entries`, `groups`. An entry has `type`
  (`totp`, `hotp`, `steam`, `motp`, `yandex`), `uuid`, `name`, `issuer`,
  `note`, `favorite`, `icon` fields, `groups` (group UUIDs) and `info`
  with `secret` (Base32), `algo`, `digits`, and `period` (TOTP, Steam) or
  `counter` (HOTP).
- Taken over: issuer, name, secret, algorithm, digits and period; Aegis,
  unlike Google, keeps the time step. Steam entries become Steam
  accounts. Not taken over: the note, icons, favorite flag and groups;
  an account carries no note in SailToken and the list has no groups.
- Skipped by position: HOTP, mOTP, Yandex and other types, MD5, and
  entries with a missing type or an unreadable secret.
- A vault or content version other than 1 and 3 is refused as a format
  SailToken does not know; only these are documented. A content that
  fails its tag after a slot opened is damaged, not a wrong password.
- Limits: file at most 16 MiB (`MAX_AEGIS_LENGTH`; icons are embedded as
  Base64 JPEG), at most 1000 entries (`MAX_ENTRIES`), scrypt `n` a power
  of two up to 2^18 with `r` at most 8 and `p` at most 4 (at most
  256 MiB, the ceiling of the Argon2 levels), names at most 1024 bytes.
- Device test (2026-10-10): an encrypted vault exported by Aegis on
  Android (scrypt n = 2^15, r = 8, p = 1) with the 12 made-up accounts
  opened with its password and brought in all of them.
- Memory: the parsed JSON, which holds every secret of a plain vault, is
  wiped string by string when the reader is done, and the decrypted
  content sits in zeroized memory. serde_json's own scratch buffers and
  scrypt's working memory are freed without wiping; neither holds a
  seed in its final form, but serde_json may have copied escaped
  strings. Recorded here as for rqrr in `docs/spike-results.md`.

## Dependencies this needs

Checked on crates.io on 2026-10-10 for `rust-version` at most 1.75 and
an edition the SDK's cargo 1.75 can parse; not yet built with `sfdk`.

| Crate | Version | Use | License |
|-------|---------|-----|---------|
| `scrypt` | 0.11.0 (rust-version 1.60, edition 2021) | Aegis password slots | MIT OR Apache-2.0 |
| `aes-gcm` | 0.10.3 (1.56, 2021) | Aegis key and content | MIT OR Apache-2.0 |
| `serde_json` | 1.x (1.0.151: 1.71, 2021), without derive | Aegis JSON | MIT OR Apache-2.0 |

`scrypt` 0.11 needs `pbkdf2` 0.12 and `salsa20` 0.10 (already vendored);
`aes-gcm` 0.10 needs `aead` 0.5 and `ghash` 0.5. The newer releases of
all of these require Rust 1.85 and edition 2024, so the versions are
pinned and the vendoring is checked with `sfdk build` before any code
depends on them. Base64 and Base32 are already in the core; the
protobuf reader is hand-written (not cryptography).
