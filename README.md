# KernelDump

[한국어](README.ko.md) · [Deployment](docs/deployment.md) · [Measurements](docs/benchmark_summary.md)

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

Actual v0.1.1 output on Ubuntu 24.04.5. JSON is formatted below; the manifest path and image hash are omitted.

```json
{
  "status": "complete_for_policy",
  "payload_bytes": 715538432,
  "elapsed_s": 2.418713536,
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
  "coverage_ranges": 14337,
  "payload_bytes": 715538432
}
```

[Capture stdout](docs/examples/capture.stdout) · [Verification stdout](docs/examples/verify.stdout).

## Tested environments

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
# Build host only: Rust 1.90.0 + x86_64-unknown-linux-musl target
python3 scripts/build_release.py
```

Version **0.1.1**. Outputs: `release/kerneldump` and an optional hash receipt. Build information records source hashes and the actual running executable hash. [Release checks](docs/release_validation.md) · [Earlier documentation](docs/history_readme_20261017_en.md).

MIT license; vendored dependencies retain their respective licenses.
