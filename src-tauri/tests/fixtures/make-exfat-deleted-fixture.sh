#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "exFAT fixture generation failed at line %s while running: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

output_dir="${1:?usage: make-exfat-deleted-fixture.sh OUTPUT_DIRECTORY}"
mkdir -p "$output_dir"
image="$output_dir/deleted-exfat.img"
expected="$output_dir/RECOVER.BIN.expected"
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
mkfs.exfat -L DCRTEST -c 4096 "$image"
sudo mount -t exfat -o loop "$image" "$mount_dir"
sudo cp "$expected" "$mount_dir/RECOVER.BIN"
sync
test -f "$mount_dir/RECOVER.BIN"
cmp "$expected" "$mount_dir/RECOVER.BIN"
sudo rm "$mount_dir/RECOVER.BIN"
sync
sudo umount "$mount_dir"
fsck.exfat -n "$image"

printf 'expected_sha256='
sha256sum "$expected"
printf 'image_sha256='
sha256sum "$image"
sha256sum "$image" | awk '{print $1}' > "$image.sha256"
