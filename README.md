# KernelDump

[Release v1.2.1](https://github.com/KKudroK/KernelDump/releases/tag/v1.2.1) includes the merged ledger, provenance, verifier and Linux 7.0 fixes. The static musl build passes 75 tests; the same binary also passed a Pod-scoped capture and verification on AWS AL2023 6.18.56. See [release files and checksums](docs/release_v9.md). Internal version: 0.1.1; policy: `kernel-focused-v9`.

The 2026-11-04 fixes were validated with existing dumps and three new captures on an exact 7.0.0-38-generic kernel in a local VM. See [kernel validation and limits](docs/kernel_7_0_0_38_validation.md) and the [initial fix notes](docs/fixes_20261104.md). Earlier performance measurements below remain historical.

[한국어](README.ko.md) · [Deployment](docs/deployment.md) · [Original comparison](docs/original_comparison.md) · [Release files](docs/release_v9.md)

`kerneldump` collects selected live kernel memory through `/proc/kcore` and `/proc/kpageflags`. It writes a LiME image, an address/coverage ledger and a manifest without loading a kernel module or stopping processes.

## Run

One static Linux x86-64 executable; no installed runtime libraries or adjacent symbol/configuration files are needed for collection.

```sh
chmod 755 kerneldump
sudo ./kerneldump check --target-dir /evidence --json
sudo ./kerneldump capture --output /evidence/new_collection
./kerneldump verify /evidence/new_collection
```

`/evidence` must exist; `new_collection` must not. `check` validates kernel access and creates, syncs and removes a temporary storage probe. It reports not-ready if storage was not specified or the checks fail. A passing check does not reserve space.

Kernel support for kcore/page monitoring, permission to read the required interfaces and unmasked required symbols are necessary. Missing kcore remains unsupported. No security settings are changed. [Requirements and failure behavior](docs/deployment.md).

Example output from the current v9 release, showing selected fields. Use the comparison table below for timing.

```json
{
  "status": "complete_for_policy",
  "payload_bytes": 656162816,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "errors": []
}
```

Verification of the same collection:

```json
{
  "verified": true,
  "status": "complete_for_policy",
  "coverage_ranges": 12300,
  "payload_bytes": 656162816
}
```

[Capture stdout](docs/examples/capture_v9.stdout) · [Verification stdout](docs/examples/verify_v9.stdout).

## Optional Pod scope

```sh
sudo ./kerneldump capture --pod <FULL_POD_UID> --output /evidence/new_collection
```

Select a Pod with `--pod`, accepting a full UID rather than a name or prefix. It limits **additional** executable-page, socket and selected-cache traversal to current Pod members; the node-wide kernel metadata filter is unchanged. Omitting it retains bounded node-wide additions. Physical pages may contain unrelated bytes.

Exact cgroup membership, PID, start time and host PID/cgroup namespace views are checked. Unknown targets and unsuitable namespace views fail without node-wide fallback. Identity changes cause partial capture. This discovers current membership, not historical ownership after a process leaves its Pod cgroup. See [validation and costs](docs/resource_retention.md).

## Executable code, queued bytes and selected cache

Policy `kernel-focused-v9` adds present ANON pages from private executable mappings, including file COW and fileless/JIT code, and FD-referenced socket queues. Current write permission is not required; retention is not an attack verdict. Socket receive/write queues, UDP reader queues and TCP retransmit/out-of-order trees retain at most 64KiB per queue, following linear bytes, page fragments and bounded frag_list links.

**Pod scope adds narrowly selected resident cache.** Open shmem/memfd and unlinked regular files up to 64KiB are considered, plus the file-cache page corresponding to each discovered executable COW page. No general file-cache sweep, arbitrary large-file prefix or file-content read to fault pages in. Comparison cache is current file content, not a trusted original.

Code, network and selected cache share 4,096 deduplicated candidate pages (at most 16MiB additional payload) and a cooperative one-second discovery deadline. Metadata candidates count against that cap; JSON metadata, process RSS and original-policy payload are outside it. Cache runs after code/network discovery and uses remaining candidate slots only: at most 256 pages including provenance metadata, 128 jobs, 100ms within the remaining shared deadline and 4MiB requested reads. Existing object/read/reference limits remain. No collection-mode switches are added.

Network layouts use running-kernel BTF. A selected Pod includes census threads with separate FD tables; unscoped collection follows process-leader FDs. Only known COW addresses are looked up in the Maple Tree, and selected file offsets in XArray. Other kernels remain unqualified for these new paths. Missing required fields, unread candidates or changed checked references cause partial capture. Per-queue windows are separately recorded. Large executable regions can still exhaust the evidence budget, including important code pages. See [scope, decision and measured costs](docs/resource_retention.md).

## Original versus current capture cost

The original **v4** had no additional executable-anonymous, socket-queue or file-cache traversal. It was compared with current **v9** on the same VM, persistent fixture and output storage. Values are medians of three captures per configuration; image size is the actual uncompressed LiME file including headers.

| Metric | Original v4 | Current v9, no Pod | Current v9, selected Pod |
|---|---:|---:|---:|
| Capture wall time | 10.11 s | 9.88 s | 9.72 s |
| Final LiME file | 617.64 MiB | 615.01 MiB | 621.64 MiB |
| Including ledger and manifest | 622.97 MiB | 620.28 MiB | 626.58 MiB |
| CPU time | 9.06 s | 9.90 s | 9.25 s |
| Peak collector RSS | 11.00 MiB | 11.25 MiB | 11.38 MiB |
| Payload added to original filter | 0.00 KiB | 8.00 KiB | 28.00 KiB |
| Capture status | Complete 3/3 | Partial 3/3 | Complete 3/3 |

With a selected Pod, wall time was **10.11s → 9.72s (-0.39s)** and the final LiME file was **617.64MiB → 621.64MiB (+4.01MiB)**. Timing ranges overlap; this does not establish a speed improvement.

Whole-image differences include changing live kernel state. Exact payload added to the original filter was **28KiB with a Pod** and **8KiB without one**. All three unscoped v9 captures were partial because some network references changed across reads. All nine images passed integrity verification; integrity is distinct from reference consistency.

The VM reported `DiskPressure` at postflight. Running Pods and restart counts were unchanged; service latency and the condition's timing effect were not measured.

[Method, limits and per-run values](docs/original_comparison.md).

## Earlier release validation

The following matrix records the earlier v4 policy and does not qualify the new BTF-dependent resource traversal.

The same x86-64 release binary was used in every row.

| Environment | Kernel | Result |
|---|---|---|
| Ubuntu 24.04.5 | 6.8.0-147 | Capture and verify passed on ext4 |
| Ubuntu 26.04, WSL2 | 6.18.33.2 | Capture and verify passed on ext4 |
| Debian 12 | 6.1.0-53-cloud-amd64 | Capture + verify; ext4, cgroup v2 |
| Debian 13 | 6.12.111+deb13-cloud-amd64 | Capture + verify; ext4, cgroup v2 |
| Rocky Linux 8.10 | 4.18.0-553.el8_10.x86_64 | Capture + verify; xfs, cgroup v1 |
| Rocky Linux 9.8 | 5.14.0-687.10.1.el9_8.0.1.x86_64 | Capture + verify; xfs, cgroup v2 |
| Kali Rolling (cloud 2026.2) | 6.18.12+kali-cloud-amd64 | Capture + verify; ext4, cgroup v2 |
| Alpine 3.16.9, cgroup v1 | 5.15.148 | Runs; capture unavailable without kcore |
| Alpine 3.22.6, cgroup v2 | 6.12.110 | Runs; capture unavailable without kcore |

Rocky retained SELinux enforcing; collection ran through sudo in an unconfined domain. Alpine lacked kcore. WSL Windows shared storage failed private-mode checks. [Test conditions](docs/distro_validation.md).

The Kali cloud archive is labelled 2026.2; its internal `VERSION_ID` is 2026.1.

## AWS comparison

Historical run on AWS EC2 `r6i.2xlarge`: Amazon Linux 2023, Linux 6.18.54, 61.78 GiB RAM and gp3 storage. A 16 GiB allocation was touched before collection and then held in memory. Values are mean ± sample standard deviation for repeated runs.

| Tool | Runs | Image size | Command elapsed | Host cache growth |
|---|---:|---:|---:|---:|
| LiME, full RAM | 1 | 62.965 GiB | 466.93 s | 40.19 GiB |
| makedumpfile `-d 31` | 5 | 2.37 ± 0.62 GiB | 1.48 ± 0.25 s* | 2.37 ± 0.62 GiB |
| **KernelDump** | **5** | **1.99 ± 0.17 GiB** | **20.84 ± 1.78 s** | **110 ± 65 KiB** |

KernelDump produced an image **96.8% smaller than full-RAM LiME**, with little observed cache growth and no LiME conversion step.

*The makedumpfile timer stops before a post-capture sync; KernelDump includes durable publication. These times are not an equal-durability speed comparison. The captures have different policies and occurred at different times. This AWS run predates v0.1.1. [Measurements and source records](docs/benchmark_summary.md).

## Volatility 3 analysis

Tested with Volatility **2.28.0**, Debian 12 / Linux **6.1.0-53**, matching DWARF symbols and four-level paging. A full image and a filtered image made from the same bytes separate filtering limits from analyzer failures.

| Result | Plugins | Observation |
|---|---|---|
| Verified kernel metadata | `pslist`, `pstree`, `sockstat`, `lsof`, `lsmod`, `mountinfo`, `ip`, `kmsg`, `ebpf` | Same records; all five test sockets retained |
| Process-memory content omitted | `psaux`, `envars`, `elfs`, `library_list`, `vmaregexscan` | Arguments, environment, ELF headers and process buffers are outside the collection policy |
| Incomplete input changes results | `process_spoofing` | Missing command lines can change `True` to `False`; `False` is not evidence of no spoofing |
| File metadata retained; content limited | `pagecache.Files`, `pagecache.RecoverFs` | Paths and inodes matched, but excluded file-cache pages prevent complete content recovery |
| Sparse-image compatibility limit | `psscan` | An unhandled missing-page read aborts the scan; also reproduced with the release binary |
| Fails on full RAM too | `sockscan`, `capabilities`, `kallsyms` | Analyzer errors; not evidence of a filtering-only fault |

Empty output from checks such as `malfind` or `check_creds` was not counted as detection success. Analysis requires matching symbols; collection still needs only the executable. [All 59 observations and failure details](docs/plugin_compatibility.md).

**`psscan` limitation:** KernelDump leaves gaps where pages are excluded. In the same-byte test, stock Volatility aborted while checking a false task candidate across one of those gaps: its missing-page exception was not handled. The full image showed an invalid exit state and PID (`-1`), so this first failure does not demonstrate a lost valid task. The gap comes from KernelDump's filtering; the scan-wide abort comes from the analyzer's handling of that gap. `psscan` is not guaranteed on these selective images, and `pslist` does not replace its search for hidden or residual tasks. No extra neighboring pages or collection options are added to work around this failure.

## Outputs and status

- `memory.lime`: selected memory with physical addresses.
- `ranges.jsonl`: selected, excluded and unavailable ranges.
- `manifest.json`: policy, source identity, errors and file hashes.

Exit **0** confirms complete capture for the recorded policy and successful persistence. **2** means incomplete capture or failed readiness; **1** means a command/setup/verification/persistence error. Preserve stderr and fragments. Collection is non-atomic, cancellation is cooperative, and SIGKILL can prevent the final manifest.

## Build and verify

```sh
./kerneldump --version
./kerneldump --build-info
# Current release built with Rust 1.93.0 + x86_64-unknown-linux-musl target
python3 scripts/build_release.py
```

Version **0.1.1**. Outputs: `release/kerneldump`, `release/manifest.json` and `release/SHA256SUMS.txt`. Build information records source hashes and the actual running executable hash. [Release checks](docs/release_validation.md) · [Earlier documentation](docs/history_readme_20261017_en.md).

MIT license; vendored dependencies retain their respective licenses.
