#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "NTFS fixture generation failed at line %s while running: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

output_dir="${1:?usage: make-ntfs-deleted-fixture.sh OUTPUT_DIRECTORY}"
mkdir -p "$output_dir"
image="$output_dir/deleted-ntfs.img"
expected="$output_dir/RECOVER.BIN.expected"
independent_recovery="$output_dir/RECOVER.BIN.sleuthkit"
mount_dir="$(mktemp -d)"
cleanup() {
  if mountpoint -q "$mount_dir"; then
    sudo umount "$mount_dir"
  fi
  rmdir "$mount_dir"
}
trap cleanup EXIT

python3 - "$expected" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(((index * 37 + 11) & 255) for index in range(65_536)))
PY

truncate -s 256M "$image"
mkntfs --force --quick --label DCRTEST "$image"
sudo mount -t ntfs-3g -o loop,rw "$image" "$mount_dir"
sudo cp "$expected" "$mount_dir/RECOVER.BIN"
sync
test -f "$mount_dir/RECOVER.BIN"
cmp "$expected" "$mount_dir/RECOVER.BIN"
sudo rm "$mount_dir/RECOVER.BIN"
sync
sudo umount "$mount_dir"

listing="$(fls -f ntfs -d -p "$image")"
line="$(printf '%s\n' "$listing" | grep -iE 'RECOVER[.]BIN$' | head -n 1 || true)"
if [[ -z "$line" ]]; then
  printf 'Sleuth Kit did not list the deleted file. Deleted-entry listing:\n%s\n' \
    "$listing" >&2
  exit 1
fi
inode="$(printf '%s\n' "$line" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+(-[0-9]+-[0-9]+)?:$/) { sub(/:.*/, "", $i); split($i, parts, "-"); print parts[1]; exit }')"
if [[ -z "$inode" ]]; then
  printf 'Could not identify the deleted entry MFT record from: %s\n' "$line" >&2
  exit 1
fi
icat -r -f ntfs "$image" "$inode" > "$independent_recovery"
cmp "$expected" "$independent_recovery"

printf 'expected_sha256='
sha256sum "$expected"
printf 'image_sha256='
sha256sum "$image"
printf 'sleuthkit_deleted_mft_record=%s\n' "$inode"
sha256sum "$image" | awk '{print $1}' > "$image.sha256"
