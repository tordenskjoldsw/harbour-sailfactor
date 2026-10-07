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
prefix='otpauth://totp/Example?secret='

write_fixture totp "$totp"
write_fixture max-length "$prefix$(repeat A $((2048 - ${#prefix})))"
write_fixture too-long "$prefix$(repeat A $((2049 - ${#prefix})))"
printf '\xff\xfe\xfd' | write_fixture invalid-utf8 -8

qrencode --version
