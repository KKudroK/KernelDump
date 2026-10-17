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

## Measured results

Historical captures on the same Ubuntu node and boot, Linux 6.8.0-146; one observation per mode on 2026-10-16. Payload size and collector elapsed time:

| Mode | Payload | Time |
|---|---:|---:|
| Full RAM | 9.663 GB | 38.27 s |
| KernelDump focused | 0.839 GB | 2.02 s |

Focused collection retained about **8.7%** of the full-RAM volume. It omits user/cache/free pages according to its policy, so it does not replace full-RAM acquisition for every investigation. The two captures occurred at different times. [Manifests and methodology](docs/benchmark_summary.md).

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
