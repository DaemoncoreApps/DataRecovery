# FAT32 reference image

The opt-in regression downloads the published `testdisk1.raw` image and its separate expected file dump from the University of Virginia CS 4414 Spring 2022 FAT-reading assignment. The assignment identifies the image as FAT32 and documents a multi-cluster root, nested directories, a contiguous multi-cluster file (`GAMECOPY.TXT`), and a noncontiguous file (`GAMEFRAG.TXT`) whose contents are expected to match. See the [assignment and fixture description](https://www.cs.virginia.edu/~cr4bd/4414/S2022/fatread.html).

The raw image is 256,098,304 bytes, SHA-256 `0ec8223d624784424bb6cce3ce4c5abc843dfc81a897bf628e9ac414c1ba48ef`. The download archive SHA-256 is `d89b30a9d916c8576df9d59400fedc1938743c496d3ba595b89a7d22423cf5c7`. The expected-dump archive SHA-256 is `d9b5e06312b64332cc32330300bb1b342d3df08e551ca979fd06c2b94f9b3061`. The test compares extracted content to the separately published dump; `GAMECOPY.TXT` and `GAMEFRAG.TXT` both hash to `e46c0dd1aab2f8eff4af8da2997eb4375ed691239428f00ff17cd3e20a2bafe3`, while `CONGRATS.TXT` hashes to `c68c86680b7c653d4bf9474bf95224bd52ea1e18eb0ae99bb7b591f1358b3a8a`.

The assignment page does not state a separate license for these reference artifacts. They are not redistributed in the repository; CI downloads the hash-pinned source archives for validation. The binary image and dump are fetched by `.github/workflows/validate.yml` at test time and are not committed. The workflow verifies both archive hashes and the extracted image hash before running `reads_independent_multicluster_fat32_reference_image`. To run it locally, set `DAEMONCORE_FAT32_REFERENCE_IMAGE` and `DAEMONCORE_FAT32_REFERENCE_DUMP` to the extracted paths, then run:

```powershell
cargo test --manifest-path ntfs-core/Cargo.toml --offline reads_independent_multicluster_fat32_reference_image -- --ignored --nocapture
```

This validates live FAT32 directory traversal and contiguous/fragmented live-file reads. It does not validate deleted-file recovery, a separately documented formatter provenance, exFAT behavior, or damaged media.
