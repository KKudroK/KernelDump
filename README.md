# KernelDump

**Version 1.4.0** unifies the previous three-step workflow (`check`, `capture`, `verify`) into a single command and adds 4 KiB AVX2 Sparse LiME hole-seeking, recycled-buffer pipelining, `16 MiB` `FLUSH_WINDOW` page-cache eviction (`POSIX_FADV_DONTNEED`), `--allow-exited-pod`, and `--max-write-mbps` write pacing. See the consolidated [code, feature, and evidence guide](docs/CODEBASE_GUIDE.md) (Korean). Historical v9, v4, AWS, and Volatility 3 results below remain prior build records.

[한국어](README.ko.md) · [Codebase guide (KO)](docs/CODEBASE_GUIDE.md) · [Deployment](docs/deployment.md) · [Original comparison](docs/original_comparison.md)

`kerneldump` collects selected live kernel memory through `/proc/kcore`, `/proc/kpageflags`, and running-kernel BTF (`/sys/kernel/btf/vmlinux`). Without loading a kernel module or stopping processes, one invocation validates readiness, writes a Sparse LiME image (`memory.lime`), range ledger (`ranges.jsonl`), and `manifest.json`, and runs inline verification (`verify_fast`).

## Run (Unified Single Command)

One static Linux x86-64 executable; no installed runtime libraries or external ISF/configuration files are needed for collection.

```sh
chmod 755 kerneldump
# Node-wide kernel-focused capture (Preflight -> Sparse LiME Capture -> Inline Verify)
sudo ./kerneldump --output /evidence/new_collection
# Pod-scoped additional retention + production write bandwidth cap
sudo ./kerneldump --output /evidence/new_collection --pod <FULL_POD_UID> --max-write-mbps 200
# Allow node-wide kernel capture on a host view even when all target Pod processes have exited
sudo ./kerneldump --output /evidence/new_collection --pod <FULL_POD_UID> --allow-exited-pod
```

`/evidence` must exist; `new_collection` must not. Production CLI options:
- `--output NEW_DIR`: new output directory
- `--pod FULL_POD_UID`: restrict additional code/socket/cache retention to one local Pod UID (node-wide kernel metadata filter stays unchanged)
- `--allow-exited-pod`: allow node-wide kernel acquisition from a valid host view when no live Pod processes remain
- `--request-id ID`: caller correlation identifier
- `--max-write-mbps 1..10000`: cap storage write bandwidth (1,000,000 B/s per unit)

Each invocation runs preflight (`probe_storage` with `SYS_renameat2(..., RENAME_NOREPLACE)`, 10% RAM / 1 GiB minimum free check, BTF 6-field probe, `/proc/kcore` / `/proc/kpageflags` sample PFN read), acquires Sparse LiME, and runs `verify_fast`. Kernel support for kcore/kpageflags/BTF and unmasked `page_offset_base` / `linux_banner` symbols are required; no security settings are changed. [Requirements and failure behavior](docs/deployment.md).

Historical v9 example output fields:

```json
{
  "status": "complete_for_policy",
  "payload_bytes": 656162816,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "errors": []
}
```

[Historical capture stdout](docs/examples/capture_v9.stdout) · [Historical verification stdout](docs/examples/verify_v9.stdout).

## Pod Scope and v1.4.0 Production Improvements

- **Strict Pod namespace view**: `--pod` requires a full Pod UID and checks `/proc/self/ns/{pid,cgroup}` against BTF `init_pid_ns` / `init_cgroup_ns`. Unsuitable namespace views (e.g., nested WSL2 PID namespaces) exit **1** without falling back silently to node-wide capture.
- **4 KiB AVX2 Sparse LiME**: Preserves all LiME headers (`0x4c694d45`), logical offsets, and full logical `lime_sha256` digests while seeking over 4 KiB all-zero pages (`allocated_file_bytes`, `sparse_zero_hole_bytes`, `actual_written_bytes`). Verified on WSL2 `6.18.33.2`: skipped `289,443,840 B` of zero writes out of `1,066,746,240 B`, reduced total elapsed time `8,347.846 ms -> 6,101.231 ms`, and matched full disk SHA-256 (`disk_sha256_equals_manifest: true`) as well as baseline full `verify`.
- **Recycled pipeline & cache eviction**: Reuses 4 MiB buffers (`recycle_tx`/`recycle_rx`) and calls `sync_file_range_write` + `POSIX_FADV_DONTNEED` every `16 MiB` (`FLUSH_WINDOW`).

## Executable Code, Socket Queues, and Selected Cache

Policy `kernel-focused` retains present ANON pages from private executable mappings (including COW and JIT/fileless code) and FD-referenced socket queues (at most `64 KiB` per queue), plus Pod-scoped resident shmem/`memfd`/unlinked regular file prefixes (up to `64 KiB`, bounded to `128` jobs per family, `512 KiB` per maps file, `64` reverse VMAs, `100 ms` / `4 MiB` cache budget). All three supplemental families share a deduplicated cap of **4,096 pages (at most 16 MiB payload)** allocated round-robin; hitting any bound or changed reference records `partial`. See [scope and measured costs](docs/resource_retention.md) and [codebase guide (KO)](docs/CODEBASE_GUIDE.md).

## Historical Benchmarks & Validation Records

### Original v4 vs v9 capture cost (historical VM record)

Comparison between **v4** (no supplemental traversal) and **v9** (node-wide vs Pod-scoped, medians of 3 runs each):

| Metric | Original v4 | v9, no Pod | v9, selected Pod |
|---|---:|---:|---:|
| Capture wall time | 10.11 s | 9.88 s | 9.72 s |
| Final LiME file | 617.64 MiB | 615.01 MiB | 621.64 MiB |
| Including ledger and manifest | 622.97 MiB | 620.28 MiB | 626.58 MiB |
| CPU time | 9.06 s | 9.90 s | 9.25 s |
| Peak collector RSS | 11.00 MiB | 11.25 MiB | 11.38 MiB |
| Payload added to original filter | 0.00 KiB | 8.00 KiB | 28.00 KiB |
| Capture status | Complete 3/3 | Partial 3/3 | Complete 3/3 |

[Method, limits and per-run values](docs/original_comparison.md).

### Earlier release validation (v4 matrix)

The table below records the earlier v4 policy and does not qualify BTF-dependent resource traversal or v1.4.0 host `--pod` capture.

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

[Test conditions](docs/distro_validation.md).

### AWS comparison (pre-v0.1.1 historical record)

Historical run on AWS EC2 `r6i.2xlarge` (Amazon Linux 2023, Linux 6.18.54, 61.78 GiB RAM, gp3) touching a 16 GiB allocation before capture (*makedumpfile timer stops before post-capture sync). [Measurements and source records](docs/benchmark_summary.md).

| Tool | Runs | Image size | Command elapsed | Host cache growth |
|---|---:|---:|---:|---:|
| LiME, full RAM | 1 | 62.965 GiB | 466.93 s | 40.19 GiB |
| makedumpfile `-d 31` | 5 | 2.37 ± 0.62 GiB | 1.48 ± 0.25 s* | 2.37 ± 0.62 GiB |
| **KernelDump** | **5** | **1.99 ± 0.17 GiB** | **20.84 ± 1.78 s** | **110 ± 65 KiB** |

### Volatility 3 compatibility limits

Tested with Volatility **2.28.0** (Debian 12 / Linux `6.1.0-53`). [All 59 observations and failure details](docs/plugin_compatibility.md).

| Result | Plugins | Observation |
|---|---|---|
| Verified kernel metadata | `pslist`, `pstree`, `sockstat`, `lsof`, `lsmod`, `mountinfo`, `ip`, `kmsg`, `ebpf` | Same records; all five test sockets retained |
| Process-memory content omitted | `psaux`, `envars`, `elfs`, `library_list`, `vmaregexscan` | Outside kernel collection policy |
| Incomplete input changes results | `process_spoofing` | Missing command lines can turn `True` into `False` |
| File metadata retained; content limited | `pagecache.Files`, `pagecache.RecoverFs` | Paths/inodes match; excluded page cache prevents full file recovery |
| Sparse-image compatibility limit | `psscan` | Unhandled missing-page exception aborts scan across excluded gaps |
| Fails on full RAM too | `sockscan`, `capabilities`, `kallsyms` | Analyzer errors |

Note: the dedicated `rrudrok` analyzer handles KernelDump v1.4.0 Sparse `memory.lime` and `ranges.jsonl` directly (`analyze --verify-hashes`, `show`, `read-memory`).

## Outputs and status

- `memory.lime`: selected memory in Sparse LiME format with physical addresses.
- `ranges.jsonl`: selected, excluded and unavailable ranges.
- `manifest.json`: policy, source identity, sparse accounting (`allocated_file_bytes`, `sparse_zero_hole_bytes`, `actual_written_bytes`), errors and hashes.

Exit **0** confirms complete capture for the policy, durability, and inline verification. **2** means incomplete capture or readiness failure; **1** means command/namespace/verification/persistence error.

## Build and verify

```sh
./kerneldump --version
./kerneldump --build-info
cargo test --offline --locked
python3 scripts/build_release.py --check-vendor
python3 scripts/build_release.py
```

Version **1.4.0**. Outputs: `release/kerneldump`, `release/manifest.json` and `release/SHA256SUMS.txt`. [Codebase guide (KO)](docs/CODEBASE_GUIDE.md) · [Development options](docs/development_options.md) · [Release checks](docs/release_validation.md) · [Earlier documentation](docs/history_readme_20261017_en.md).

MIT license; vendored dependencies retain their respective licenses.
