#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: make-raid5-reference-fixture.sh OUTPUT_DIR [LAYOUT] [MEMBER_COUNT]}
layout=${2:-left-symmetric}
member_count=${3:-3}
case "$layout" in
  left-asymmetric|right-asymmetric|left-symmetric|right-symmetric) ;;
  *)
    echo "unsupported RAID 5 layout: $layout" >&2
    exit 2
    ;;
esac
if (( member_count < 3 || member_count > 4 )); then
  echo "independent reference member count must be 3 or 4" >&2
  exit 2
fi
mkdir -p "$output_dir"
output_dir=$(realpath "$output_dir")
if compgen -G "$output_dir/member*.raw" >/dev/null || compgen -G "$output_dir/member*.disk" >/dev/null; then
  echo "output directory already contains RAID member files: $output_dir" >&2
  exit 2
fi

member_bytes=$((8 * 1024 * 1024))
# Reserve a small tail for metadata 1.0 while keeping mdadm's component-size
# difference below its 1% warning threshold.
backing_bytes=$((member_bytes + 64 * 1024))
logical_bytes=$((member_bytes * (member_count - 1)))
array=/dev/md/daemoncore-raid5-reference-${member_count}-$$
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
  --level=5 \
  --layout="$layout" \
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
import os
import pathlib
import sys

array = pathlib.Path(sys.argv[1])
expected_path = pathlib.Path(sys.argv[2])
size = int(sys.argv[3])
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
printf '%s\n' "$layout" > "$output_dir/layout.txt"
(
  cd "$output_dir"
  sha256sum member*.raw logical-image.raw > SHA256SUMS
  sha256sum --check SHA256SUMS
)
