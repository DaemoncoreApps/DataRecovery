# NTFS parser fuzzing

The target calls the same `daemoncore-ntfs-core` parser used by the Windows
application. The checked-in corpus includes valid empty and resident-file MFT
records plus coverage-increasing inputs from bounded fuzz runs.

Run from `src-tauri` on a supported Linux host with Rust nightly, Clang, and
`cargo-fuzz` installed:

```sh
cargo +nightly fuzz run ntfs_parse_record -- -max_len=1024
```

For a bounded CI or release check, add a run count and time limit:

```sh
cargo +nightly fuzz run ntfs_parse_record -- -runs=1000000 -max_total_time=120 -max_len=1024
```

Preserve the corpus and any crash artifacts with the source revision they came
from. A bounded run is only a smoke campaign; production qualification still
requires sustained campaigns and triage of every artifact.
