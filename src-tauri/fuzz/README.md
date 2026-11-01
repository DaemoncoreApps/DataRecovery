# NTFS parser fuzzing

Both targets call the same `daemoncore-ntfs-core` code used by the Windows
application. `ntfs_parse_record` focuses on individual MFT records.
`ntfs_scan_image` starts at the NTFS volume boundary and runs the bounded scan,
including boot geometry, MFT reads, resident/nonresident attribute lists, and
extension-record resolution. Its checked-in seed images are synthetic
regression fixtures, not independent production-volume evidence.

Run from `src-tauri` on a supported Linux host with Rust nightly, Clang, and
`cargo-fuzz` installed:

```sh
cargo +nightly fuzz run ntfs_parse_record -- -max_len=1024
cargo +nightly fuzz run ntfs_scan_image -- -max_len=4194304
```

For a bounded CI or release check, add a run count and time limit:

```sh
cargo +nightly fuzz run ntfs_parse_record -- -runs=1000000 -max_total_time=120 -max_len=1024
cargo +nightly fuzz run ntfs_scan_image -- -runs=1000000 -max_total_time=120 -max_len=4194304
```

The three whole-image seeds are generated from the regression fixture builders
by running `ntfs_tests::emit_ntfs_fuzz_seeds` with
`DAEMONCORE_FUZZ_SEED_DIRECTORY` set to
`src-tauri/fuzz/corpus/ntfs_scan_image`. The ignored test uses create-new file
semantics and will not overwrite existing corpus files.

Preserve the corpus and any crash artifacts with the source revision they came
from. A bounded run is only a smoke campaign; production qualification still
requires sustained campaigns and triage of every artifact.
