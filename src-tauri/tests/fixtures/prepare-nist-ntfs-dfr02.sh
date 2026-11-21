#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: prepare-nist-ntfs-dfr02.sh OUTPUT_DIRECTORY}
mkdir -p "$output_dir"
output_dir=$(realpath "$output_dir")
archive="$output_dir/dfr-02-ntfs.dd.bz2"
image="$output_dir/dfr-02-ntfs.dd"
expected="$output_dir/Bunda.txt.sleuthkit"

for path in "$archive" "$image" "$expected"; do
  if [[ -e "$path" ]]; then
    echo "refusing to overwrite existing reference fixture: $path" >&2
    exit 2
  fi
done

curl --fail --location --retry 3 \
  https://cfreds-archive.nist.gov/dfr-images/dfr-02-ntfs.dd.bz2 \
  --output "$archive"
printf '%s  %s\n' \
  18ff23026ad7ed8fe6d93eca00200b0ede031c6ee4e760f52e62aee397d87844 "$archive" \
  | sha256sum --check

bzip2 --decompress --keep "$archive"
printf '%s  %s\n' \
  57e6f37d3312ee4a113a6534a1ffcbd45ad3e0325a509442ac54ae632762d1ef "$image" \
  | sha256sum --check

listing=$(fls -o 61 -f ntfs -d -p "$image")
inode=$(printf '%s\n' "$listing" | awk '
  $NF == "Bunda.txt" {
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^[0-9]+-[0-9]+-[0-9]+:$/) {
        split($i, parts, "-")
        print parts[1]
        exit
      }
    }
  }
')
if [[ -z "$inode" ]]; then
  printf 'NIST DFR-02 deleted Bunda.txt entry was not found:\n%s\n' "$listing" >&2
  exit 1
fi

icat -o 61 -f ntfs -r "$image" "$inode" > "$expected"
printf '%s  %s\n' \
  c6c07acfb00ad4e8567f583c2aadec51d212f13eb3482e3514e89986df6c9503 "$expected" \
  | sha256sum --check
test "$(stat --format=%s "$expected")" -eq 8192
istat -o 61 -f ntfs "$image" "$inode" | tee "$output_dir/Bunda.txt.istat"
printf 'nist_dfr02_deleted_mft_record=%s\n' "$inode"
