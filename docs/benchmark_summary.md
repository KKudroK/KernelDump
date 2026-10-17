# Measurement notes

The README table comes from [full-RAM](benchmark_data/full_ram_manifest.json) and [focused-v4](benchmark_data/focused_manifest.json) manifests: 9,662,648,320 versus 839,311,360 payload bytes, and 38.2701389 versus 2.018971632 collector seconds. Decimal GB is used. Both record the same boot ID and Linux 6.8.0-146, with complete-for-policy status, but different capture times. Full RAM was acquired with the development full-RAM mode of this collector, not an asserted LiME-module benchmark.

The smaller focused result follows a different PFN selection policy. It does not establish full-RAM-equivalent evidence, atomicity or universal analysis coverage. The earlier 64-GiB/AWS table was not selected for the concise README because its original comparison records were not verified in this task. It remains in the archived README as historical documentation.

## 2026-10-17 regression smoke test

| Tool | Before wall | After wall | CPU before → after | Max RSS before → after |
|---|---:|---:|---:|---:|
| poddump | 0.320 s | 0.267 s | 0.28 → 0.23 s | 92.32 → 90.23 MiB |
| kerneldump | 2.690 s | 2.532 s | 3.39 → 3.14 s | 11.25 → 11.25 MiB |

One old/new capture per tool on Ubuntu 24.04.5/Linux 6.8.0-147, using the existing Kubernetes VM and ext4 storage. The old executable ran first; there was no cache reset or repeat. Wall time is measured around process launch through exit (including durable publication); CPU/max RSS come from GNU time and exclude evidence export. This check found no gross regression; it does not establish a speedup or statistical equivalence.

PodDump used the same 64-MiB patterned, four-thread fixture process plus sandbox, with unchanged PID/start-time identities. Both produced 101,797,888 logical core bytes; all 128 MiB of fixture pattern across the two cores matched. KernelDump's live PFN payload changed from 739,835,904 to 715,538,432 bytes, so its timing is not a fixed-byte comparison. Both images verified. No performance optimization was made.

[Exact smoke observations and binary hashes](performance_smoke.json). Earlier comparison sources and SHA-256 values: [benchmark_sources.json](benchmark_sources.json).
