#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: make-raid5-reference-fixture.sh OUTPUT_DIR}
mkdir -p "$output_dir"
output_dir=$(realpath "$output_dir")

member_bytes=$((8 * 1024 * 1024))
backing_bytes=$((member_bytes + 1024 * 1024))
array=/dev/md/daemoncore-raid5-reference-$$
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

for member in 0 1 2; do
  backing="$output_dir/member${member}.disk"
  truncate --size="$backing_bytes" "$backing"
  loop_devices+=("$(losetup --find --show "$backing")")
done

array_started=1
mdadm --create "$array" \
  --metadata=1.0 \
  --level=5 \
  --layout=left-symmetric \
  --raid-devices=3 \
  --chunk=64K \
  --size=8192K \
  --assume-clean \
  --run \
  "${loop_devices[@]}"
udevadm settle
[[ -b "$array" ]]
[[ $(blockdev --getsize64 "$array") -eq $((member_bytes * 2)) ]]

python3 - "$array" "$output_dir/logical-image.raw" <<'PY'
import os
import pathlib
import sys

array = pathlib.Path(sys.argv[1])
expected_path = pathlib.Path(sys.argv[2])
size = 16 * 1024 * 1024
expected = bytes((index * 31 + (index >> 12) * 17 + (index >> 20)) & 0xff for index in range(size))
expected_path.write_bytes(expected)
with array.open("r+b", buffering=0) as device:
    device.write(expected)
    os.fsync(device.fileno())
with array.open("rb", buffering=0) as device:
    observed = device.read(size)
if observed != expected:
    raise SystemExit("Linux MD RAID 5 reference array did not return the written logical bytes")
PY
echo "ae6018b38e30a433a0505035cf4df582da77c7ef92c269245232686e541e97c8  $output_dir/logical-image.raw" | sha256sum --check

mdadm --stop "$array"
array_started=0
for member in 0 1 2; do
  dd if="$output_dir/member${member}.disk" \
    of="$output_dir/member${member}.raw" \
    bs=1M count=8 iflag=fullblock status=none
done
chmod 0644 "$output_dir"/member*.raw "$output_dir/logical-image.raw"
(
  cd "$output_dir"
  sha256sum member0.raw member1.raw member2.raw logical-image.raw > SHA256SUMS
)
