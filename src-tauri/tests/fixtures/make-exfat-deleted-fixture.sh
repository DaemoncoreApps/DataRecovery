#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "exFAT fixture generation failed at line %s while running: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

output_dir="${1:?usage: make-exfat-deleted-fixture.sh OUTPUT_DIRECTORY}"
mkdir -p "$output_dir"
image="$output_dir/deleted-exfat.img"
expected="$output_dir/RECOVER.BIN.expected"
chain_image="$output_dir/deleted-exfat-chain.img"
chain_expected="$output_dir/RECOVER_CHAIN.BIN.expected"
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
cp "$expected" "$chain_expected"

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

# Force the target's second extent past an allocated cluster, then free that
# interleaving file so every target cluster is free while its FAT chain remains.
truncate -s 256M "$chain_image"
mkfs.exfat -L DCRCHAIN -c 4096 "$chain_image"
sudo mount -t exfat -o loop "$chain_image" "$mount_dir"
sudo dd if="$chain_expected" of="$mount_dir/RECOVER_CHAIN.BIN" bs=4096 count=8 status=none
sudo dd if=/dev/zero of="$mount_dir/INTERLEAVE.BIN" bs=4096 count=1 status=none
sudo dd if="$chain_expected" of="$mount_dir/RECOVER_CHAIN.BIN" bs=4096 skip=8 count=8 \
  oflag=append conv=notrunc status=none
sync
cmp "$chain_expected" "$mount_dir/RECOVER_CHAIN.BIN"
sudo rm "$mount_dir/INTERLEAVE.BIN"
sudo rm "$mount_dir/RECOVER_CHAIN.BIN"
sync
sudo umount "$mount_dir"
fsck.exfat -n "$chain_image"

python3 - "$chain_image" "$chain_expected" <<'PY'
from pathlib import Path
import struct
import sys

image_path, expected_path = map(Path, sys.argv[1:])
expected = expected_path.read_bytes()
with image_path.open("rb") as image:
    boot = image.read(512)
    sector_size = 1 << boot[108]
    cluster_size = sector_size << boot[109]
    fat_offset = struct.unpack_from("<I", boot, 80)[0] * sector_size
    heap_offset = struct.unpack_from("<I", boot, 88)[0] * sector_size
    cluster_count = struct.unpack_from("<I", boot, 92)[0]
    root_cluster = struct.unpack_from("<I", boot, 96)[0]

def fat_next(cluster):
    with image_path.open("rb") as image:
        image.seek(fat_offset + cluster * 4)
        return struct.unpack("<I", image.read(4))[0] & 0x0FFFFFFF

root_clusters = []
seen_root_clusters = set()
current = root_cluster
while current < 0x0FFFFFF8:
    if not 2 <= current <= cluster_count + 1:
        raise SystemExit("root FAT chain points outside the cluster heap")
    if current in seen_root_clusters or len(root_clusters) >= 1_000_000:
        raise SystemExit("root FAT chain is cyclic or excessive")
    seen_root_clusters.add(current)
    root_clusters.append(current)
    current = fat_next(current)
with image_path.open("rb") as image:
    root_bytes = bytearray()
    for cluster in root_clusters:
        image.seek(heap_offset + (cluster - 2) * cluster_size)
        root_bytes.extend(image.read(cluster_size))

records = []
for offset in range(0, len(root_bytes), 32):
    record = bytes(root_bytes[offset : offset + 32])
    if record[0] == 0:
        break
    records.append(record)

target = None
for index, record in enumerate(records):
    if record[0] & 0x7F != 0x05:
        continue
    secondary_count = record[1]
    entry_set = records[index : index + secondary_count + 1]
    stream = next((item for item in entry_set[1:] if item[0] & 0x7F == 0x40), None)
    name_units = []
    for item in entry_set[1:]:
        if item[0] & 0x7F == 0x41:
            name_units.extend(struct.unpack_from("<15H", item, 2))
    name = "".join(chr(unit) for unit in name_units if unit)
    if name == "RECOVER_CHAIN.BIN":
        if record[0] & 0x80 or stream is None or stream[0] & 0x80:
            raise SystemExit("target entry was not preserved as a deleted entry set")
        if stream[1] & 0x02:
            raise SystemExit("target is marked contiguous; fixture did not force a FAT chain")
        first_cluster = struct.unpack_from("<I", stream, 20)[0]
        data_length = struct.unpack_from("<Q", stream, 24)[0]
        target = first_cluster, data_length
        break

if target is None:
    raise SystemExit("deleted RECOVER_CHAIN.BIN entry was not found")
first_cluster, data_length = target
if data_length != len(expected):
    raise SystemExit(f"unexpected target stream length: {data_length}")
clusters = []
seen_clusters = set()
current = first_cluster
while len(clusters) * cluster_size < data_length:
    if not 2 <= current <= cluster_count + 1:
        raise SystemExit("target FAT chain points outside the cluster heap")
    if current in seen_clusters or len(clusters) >= 1_000_000:
        raise SystemExit("target FAT chain is invalid or cyclic")
    seen_clusters.add(current)
    clusters.append(current)
    current = fat_next(current)
if all(right == left + 1 for left, right in zip(clusters, clusters[1:])):
    raise SystemExit("target clusters are contiguous; expected a fragmented fixture")

recovered = bytearray()
with image_path.open("rb") as image:
    for cluster in clusters:
        image.seek(heap_offset + (cluster - 2) * cluster_size)
        recovered.extend(image.read(cluster_size))
if bytes(recovered[:data_length]) != expected:
    raise SystemExit("retained exFAT FAT chain does not map back to original bytes")
print(f"deleted FAT-chain clusters={clusters}")
PY

printf 'expected_sha256='
sha256sum "$expected"
printf 'image_sha256='
sha256sum "$image"
sha256sum "$image" | awk '{print $1}' > "$image.sha256"
printf 'chain_expected_sha256='
sha256sum "$chain_expected"
printf 'chain_image_sha256='
sha256sum "$chain_image"
sha256sum "$chain_image" | awk '{print $1}' > "$chain_image.sha256"
