#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "FAT32 fixture generation failed at line %s while running: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

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
directory_listing="$(mdir -i "$image" ::)"
if ! printf '%s\n' "$directory_listing" | grep -qiE 'RECOVER([.]|[[:space:]])+BIN'; then
  printf 'RECOVER.BIN is missing immediately after mcopy. FAT32 root listing:\n%s\n' \
    "$directory_listing" >&2
  exit 1
fi
mdel -i "$image" ::RECOVER.BIN
fsck.fat -vn "$image" >/dev/null

listing="$(fls -f fat32 -d -p "$image")"
if ! printf '%s\n' "$listing" | grep -iE 'RECOVER\.BIN$'; then
  printf 'Sleuth Kit did not list the deleted file. Deleted-entry listing:\n%s\n' \
    "$listing" >&2
  exit 1
fi
inode="$(printf '%s\n' "$listing" | awk 'toupper($0) ~ /RECOVER\.BIN$/ { for (i = NF; i > 0; i--) if ($i ~ /^[0-9]+:$/) { sub(/:$/, "", $i); print $i; exit } }')"
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
