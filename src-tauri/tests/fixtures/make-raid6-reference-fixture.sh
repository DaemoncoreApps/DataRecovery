#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: make-raid6-reference-fixture.sh OUTPUT_DIR [MEMBER_COUNT]}
member_count=${2:-4}
if (( member_count < 4 || member_count > 16 )); then
  echo "member count must be between 4 and 16" >&2
  exit 2
fi
mkdir -p "$output_dir"
output_dir=$(realpath "$output_dir")
if compgen -G "$output_dir/member*.raw" >/dev/null || compgen -G "$output_dir/member*.disk" >/dev/null; then
  echo "output directory already contains RAID member files: $output_dir" >&2
  exit 2
fi

member_bytes=$((8 * 1024 * 1024))
logical_bytes=$((member_bytes * (member_count - 2)))
backing_bytes=$((member_bytes + 1024 * 1024))
array=/dev/md/daemoncore-raid6-reference-$$
loop_devices=()
array_started=0

cleanup() {
  if (( array_started )); then
    mdadm --stop "$array" >/dev/null || true
  fi
  for ((index=${#loop_devices[@]}-1; index>=0; index--)); do
    losetup --detach "${loop_devices[index]}" || true
  done
}
trap cleanup EXIT

for ((member=0; member<member_count; member++)); do
  backing="$output_dir/member${member}.disk"
  truncate --size="$backing_bytes" "$backing"
  loop_devices+=("$(losetup --find --show "$backing")")
done

array_started=1
mdadm --create "$array" \
  --metadata=1.0 \
  --level=6 \
  --layout=left-symmetric \
  --raid-devices="$member_count" \
  --chunk=64K \
  --size=8192K \
  --assume-clean \
  --run \
  "${loop_devices[@]}"
udevadm settle
[[ -b "$array" ]]
[[ $(blockdev --getsize64 "$array") -eq "$logical_bytes" ]]

python3 - "$array" "$output_dir/logical-image.raw" "$logical_bytes" <<'PY'
import pathlib
import sys

array = pathlib.Path(sys.argv[1])
expected_path = pathlib.Path(sys.argv[2])
size = int(sys.argv[3])
expected = bytes((index * 31 + (index >> 12) * 17 + (index >> 20)) & 0xff for index in range(size))
expected_path.write_bytes(expected)
with array.open("r+b", buffering=0) as device:
    device.write(expected)
    import os
    os.fsync(device.fileno())
with array.open("rb", buffering=0) as device:
    observed = device.read(size)
if observed != expected:
    raise SystemExit("Linux MD RAID 6 reference array did not return the written logical bytes")
PY
sha256sum "$output_dir/logical-image.raw" > "$output_dir/logical-image.sha256"
sha256sum --check "$output_dir/logical-image.sha256"

mdadm --stop "$array"
array_started=0
for ((member=0; member<member_count; member++)); do
  dd if="$output_dir/member${member}.disk" \
    of="$output_dir/member${member}.raw" \
    bs=1M count=8 iflag=fullblock status=none
done
chmod 0644 "$output_dir"/member*.raw "$output_dir/logical-image.raw"
(
  cd "$output_dir"
  sha256sum member*.raw logical-image.raw > SHA256SUMS
  sha256sum --check SHA256SUMS
)
