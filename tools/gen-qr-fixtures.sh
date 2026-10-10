#!/usr/bin/env bash
# Writes the QR code test fixtures in core/tests/fixtures/qr: one line per
# module row, '#' for a dark module and '.' for a light one, without a quiet
# zone. The tests render them into gray frames. Payloads are made up.
#
# Usage: tools/gen-qr-fixtures.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fixtures="$root/core/tests/fixtures/qr"
mkdir -p "$fixtures"

write_fixture() {
    local name=$1
    shift
    qrencode -t ASCII -m 0 "$@" | sed -e 's/##/#/g' -e 's/  /./g' > "$fixtures/$name.txt"
}

repeat() {
    printf "%*s" "$2" "" | tr ' ' "$1"
}

totp='otpauth://totp/Example:alice@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Example'

write_fixture totp "$totp"
# Only characters of QR's alphanumeric mode, which holds up to 4296 of
# them, so a code can go past the payload limit of 4096 bytes; byte mode
# ends at 2953.
long='OTPAUTH://TOTP/EXAMPLE:'
write_fixture max-length "$long$(repeat A $((4096 - ${#long})))"
write_fixture too-long "$long$(repeat A $((4097 - ${#long})))"
printf '\xff\xfe\xfd' | write_fixture invalid-utf8 -8

# A Google Authenticator export of two codes (batch 42) with made-up
# accounts: code 1 holds alice@example.org at Example (SHA1, six digits,
# secret JBSWY3DPEHPK3PXP); code 2 holds bob at Other (SHA256, eight
# digits, secret "made-up-import-seed!") and the counter-based carol.
write_fixture export-1-of-2 'otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUub3JnGgdFeGFtcGxlIAEoATACEAEYAiAAKCo%3D'
write_fixture export-2-of-2 'otpauth-migration://offline?data=CikKFG1hZGUtdXAtaW1wb3J0LXNlZWQhEglPdGhlcjpib2IaACACKAIwAgoiCgpIZWxsbyHerb7vEgVjYXJvbBoHQ291bnRlciABKAEwARABGAIgASgq'

qrencode --version
