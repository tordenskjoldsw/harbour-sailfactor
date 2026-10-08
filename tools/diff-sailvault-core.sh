#!/usr/bin/env bash
# Checks the code copied from SailVault (PLAN.md section 5). Fails when a
# copied file differs from SailVault at the commit it was copied from, or
# when SailVault changed one of these files after that commit. After
# porting such a change, set copied_from to the SailVault commit it came
# from.
#
# Usage: tools/diff-sailvault-core.sh [path to SailVault]
set -euo pipefail

copied_from=8a9efffe69e6b8157ce82de58e8dbcc30d2bc8de
root=$(cd "$(dirname "$0")/.." && pwd)
sailvault=${1:-"$root/../SailVault"}
paths=(
    core/src/kdbx
    core/src/secret.rs
    core/src/random.rs
    core/src/argon2_memory.rs
    core/tests/fixtures/README.md
    core/tests/fixtures/fixture.keyx
    core/tests/fixtures/kdbx31-aeskdf.kdbx
    core/tests/fixtures/kdbx31-aeskdf-keyfile.kdbx
    core/tests/fixtures/kdbx4-1000-entries.kdbx
    core/tests/fixtures/kdbx4-aes-aeskdf.kdbx
    core/tests/fixtures/kdbx4-aes-aeskdf-keyfile.kdbx
    core/tests/fixtures/kdbx4-aes-argon2d.kdbx
    core/tests/fixtures/kdbx4-chacha20-argon2id.kdbx
    core/tests/fixtures/kdbx4-twofish-aeskdf.kdbx
    tools/gen-kdbx-fixtures.sh
    tools/kdbx-fixtures
)

drift=0
copied=$(git -C "$sailvault" ls-tree -r --name-only "$copied_from" -- "${paths[@]}")
for file in $copied; do
    if [[ ! -f "$root/$file" ]]; then
        echo "missing here: $file"
        drift=1
    elif ! git -C "$sailvault" show "$copied_from:$file" | cmp -s - "$root/$file"; then
        echo "differs from SailVault ${copied_from:0:7}: $file"
        drift=1
    fi
done
while IFS= read -r file; do
    if ! grep -qxF "$file" <<<"$copied"; then
        echo "only here: $file"
        drift=1
    fi
done < <(cd "$root" && find core/src/kdbx tools/kdbx-fixtures -type f | sort)

changed=$(git -C "$sailvault" diff --name-only "$copied_from" HEAD -- "${paths[@]}")
if [[ -n $changed ]]; then
    echo "changed in SailVault after ${copied_from:0:7}, to be ported:"
    sed 's/^/  /' <<<"$changed"
    drift=1
fi

if ((drift == 0)); then
    echo "copy matches SailVault ${copied_from:0:7}, no newer changes"
fi
exit "$drift"
