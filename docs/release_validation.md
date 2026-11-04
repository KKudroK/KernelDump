# Release validation — 2026-10-17

This is the historical v4 deployment record. Current v9 resource retention, limits and measured costs are documented in [resource retention](resource_retention.md); the old compatibility matrix does not qualify the new BTF paths.

The supported Linux x86-64 deployment is qualified within [documented kernel/access/storage requirements](deployment.md). No universal Linux/cloud/LSM/network-filesystem claim is made.

- Production static musl builds: PodDump 62 unit tests; KernelDump 40. No dynamic interpreter/shared-library dependency; development features absent. The distribution build helper reproduced the same executable hashes.
- Ubuntu Kubernetes VM: 34 failure/recovery CLI invocations, 11 readiness checks/capture refusals and 8 admission cases. Same active request ID links with exit 3; different requests serialize and rediscover; waiting cancellation and SIGKILL lock recovery passed.
- Normal, non-root/missing capabilities, FD/size/address-space limits, existing/symlink/read-only outputs, low disk, runtime ENOSPC, SIGINT/SIGTERM/SIGKILL, pre-existing group stop and truncated-image verification were exercised. The 32-MiB KernelDump address-space case successfully captured and independently verified; failure was not required by that resource limit. A preserved pre-existing stop is intentional.
- Stability phase: 19 independently parsed ELF cores, including 9 complete fixture patterns totaling 384 MiB. The one-shot regression check added 4 valid cores and 128 MiB of matching fixture pattern. 832 HTTP probes in the stability suite had zero errors at a two-second timeout; this is not a service SLO or soak test.
- Identical binaries on Ubuntu 24.04.5/Linux 6.8.0-147 and Ubuntu 26.04/WSL2 Linux 6.18.33.2 captured successfully. Booted Alpine 3.16.9/Linux 5.15.148/cgroup v1 and Alpine 3.22.6/Linux 6.12.110/cgroup v2 each passed three synthetic runtime-layout Pod captures. Alpine KernelDump correctly refused absent kcore. Only the Ubuntu VM ran real Kubernetes/containerd.
- 22 current capture manifests matched independently hashed executable files. Source hashes match the distributed sources. 209 VM evidence files (2,618,600,248 bytes), 38 regression files (1,718,849,349 bytes), and WSL evidence were copied and hash-verified on the experiment drive.
- Both postflights retained the 13 existing Running Pod UIDs/restart counts, Node Ready and no pressure conditions. Owned test namespaces were removed; no owned collector/fixture process remained.

| Tool | Before wall | After wall | CPU before → after | Max RSS before → after |
|---|---:|---:|---:|---:|
| poddump | 0.320 s | 0.267 s | 0.28 → 0.23 s | 92.32 → 90.23 MiB |
| kerneldump | 2.690 s | 2.532 s | 3.39 → 3.14 s | 11.25 → 11.25 MiB |

This is one observation per binary/tool. See [methodology](benchmark_summary.md) for changing live payload and order/cache limits. No performance tuning was performed.

The experiment record is `collector_portable_release_20261017`. The previous audit `collector_deploy_stability_20261017` remains separate and immutable. Known limits include per-process stops/non-atomic collection, cooperative kernel-I/O cancellation, no final manifest after SIGKILL, and no reservation of free disk space.

## Additional distribution checks

The unchanged binaries also passed Debian 12/13, Rocky Linux 8/9 and Kali cloud-image tests: 15 Pod cores with 240 MiB of matching known data, five KernelDump captures/verifications and 75 CLI invocations including expected refusals. See the [exact VM matrix and limits](distro_validation.md). This is additional compatibility coverage; the earlier failure/recovery suite above remains a separate test phase.
