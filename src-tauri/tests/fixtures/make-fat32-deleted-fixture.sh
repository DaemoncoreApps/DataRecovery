#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:?usage: make-fat32-deleted-fixture.sh OUTPUT_DIRECTORY}"
mkdir -p "$output_dir"
image="$output_dir/deleted-fat32.img"
expected="$output_dir/RECOVER.BIN.expected"
independent_recovery="$output_dir/RECOVER.BIN.sleuthkit"

python3 - "$expected" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(range(256)) * 256)
PY
touch -d "2020-01-01T00:00:00Z" "$expected"

truncate -s 128M "$image"
mkfs.vfat -F 32 -s 1 -n DCRTEST -i 0xDCDC0201 "$image"
mcopy -i "$image" "$expected" ::RECOVER.BIN
mdir -i "$image" :: | grep -F 'RECOVER.BIN' >/dev/null
mdel -i "$image" ::RECOVER.BIN
fsck.fat -vn "$image" >/dev/null

listing="$(fls -f fat32 -d -p "$image")"
printf '%s\n' "$listing" | grep -E 'RECOVER\.BIN$'
inode="$(printf '%s\n' "$listing" | awk '/RECOVER\.BIN$/ { for (i = NF; i > 0; i--) if ($i ~ /^[0-9]+:$/) { sub(/:$/, "", $i); print $i; exit } }')"
if [[ -z "$inode" ]]; then
  echo "Could not identify the deleted entry's Sleuth Kit metadata address" >&2
  exit 1
fi
icat -f fat32 "$image" "$inode" > "$independent_recovery"
cmp "$expected" "$independent_recovery"
printf 'expected_sha256='
sha256sum "$expected"
printf 'image_sha256='
sha256sum "$image"
printf 'sleuthkit_deleted_entry=%s\n' "$inode"
