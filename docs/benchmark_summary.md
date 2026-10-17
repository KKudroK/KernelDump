# Measurement notes

## AWS EC2 comparison reviewed on 2026-10-17

The README uses [saved observations](benchmark_data/aws_64gb_results.json), checked against the original measurement script. All five-sample means and sample standard deviations were recalculated. This is a historical experiment, not a new performance run of v0.1.1.

- The host was recorded as EC2 r6i.2xlarge / Amazon Linux 2023 / Linux 6.18.54-121.166.amzn2023.x86_64, 61.78 GiB RAM and gp3 storage. The fixture allocates 16 GiB, touches every 4 KiB page, then sleeps. It does not continuously mutate memory or spawn workers.
- KernelDump ran five times, followed by five makedumpfile runs. The LiME baseline is one earlier run loaded into the summary. There was no randomized order or equal-byte workload.
- KernelDump measures process launch through exit, including its durable publication contract. makedumpfile uses `-d 31` (compressed output), and the timer excludes a post-capture sync. A pre-run `sync` does not make the preceding timer include writeback.
- The historical 13.406 s acquisition / 34.437 s total / 39.5% advantage claim mixes a five-run compressed-format average with separately reported sync and ELF-to-LiME conversion observations. Those component receipts are not in the saved benchmark JSON; this is not presented as a measured pipeline comparison.
- Cache values are changes in host `/proc/meminfo` Cached at command boundaries, not peak memory use, process RSS or an absence of service impact. Linux meminfo kB values are converted as KiB; 42,144,724 KiB is 40.19 GiB, not 42.14 GiB.
- KernelDump's 2,041.52 MiB mean image is 96.8% smaller than the recorded 67,608,031,360-byte LiME baseline. It omits memory according to its policy; size reduction is not evidence equivalence. Elapsed time alone does not measure pointer consistency or prove reduced forensic smear.

The [AWS manifest](benchmark_data/aws_capture_manifest.json) records the older build and scope. Its legacy embedded executable hash is not used to identify the current release. [Six AWS plugin observations](benchmark_data/aws_plugin_results.json) show successful execution, including sockstat; differing record counts are not a completeness or accuracy score.

## Earlier local comparison

The earlier local comparison comes from [full-RAM](benchmark_data/full_ram_manifest.json) and [focused-v4](benchmark_data/focused_manifest.json) manifests: 9,662,648,320 versus 839,311,360 payload bytes, and 38.2701389 versus 2.018971632 collector seconds. Decimal GB is used. Both record the same boot ID and Linux 6.8.0-146, with complete-for-policy status, but different capture times. Full RAM was acquired with the development full-RAM mode of this collector, not an asserted LiME-module benchmark.

The smaller focused result follows a different PFN selection policy. It does not establish full-RAM-equivalent evidence, atomicity or universal analysis coverage. The AWS records were subsequently inspected for the current README; the limits below replace the earlier unchecked AWS summary.

## 2026-10-17 regression smoke test

| Tool | Before wall | After wall | CPU before → after | Max RSS before → after |
|---|---:|---:|---:|---:|
| poddump | 0.320 s | 0.267 s | 0.28 → 0.23 s | 92.32 → 90.23 MiB |
| kerneldump | 2.690 s | 2.532 s | 3.39 → 3.14 s | 11.25 → 11.25 MiB |

One old/new capture per tool on Ubuntu 24.04.5/Linux 6.8.0-147, using the existing Kubernetes VM and ext4 storage. The old executable ran first; there was no cache reset or repeat. Wall time is measured around process launch through exit (including durable publication); CPU/max RSS come from GNU time and exclude evidence export. This check found no gross regression; it does not establish a speedup or statistical equivalence.

PodDump used the same 64-MiB patterned, four-thread fixture process plus sandbox, with unchanged PID/start-time identities. Both produced 101,797,888 logical core bytes; all 128 MiB of fixture pattern across the two cores matched. KernelDump's live PFN payload changed from 739,835,904 to 715,538,432 bytes, so its timing is not a fixed-byte comparison. Both images verified. No performance optimization was made.

[Exact smoke observations and binary hashes](performance_smoke.json). Earlier comparison sources and SHA-256 values: [benchmark_sources.json](benchmark_sources.json).
