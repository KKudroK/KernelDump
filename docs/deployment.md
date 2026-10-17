# Standalone deployment — 2026-10-17

The executable is `kerneldump` (0.1.1), a static PIE for little-endian Linux x86-64 with 4-KiB pages. Copy this one file and make it executable. No glibc, Rust, Python, kernel module, symbol bundle, daemon or adjacent metadata file is needed for collection. Offline analysis may separately require matching symbols and analysis tools.

```sh
chmod 755 kerneldump
./kerneldump --version
./kerneldump --build-info
sudo ./kerneldump check --target-dir /evidence --json
sudo ./kerneldump capture --output /evidence/new_collection --request-id incident_001
./kerneldump verify /evidence/new_collection
```

## Readiness and environment

`--target-dir` is an **existing parent directory** on the intended output filesystem, not the new capture directory. The check briefly creates a new private child and file, writes bytes, fsyncs, publishes without replacement, syncs directories and removes the probe. Failures, including cleanup errors, are reported. No supplied file is overwritten. Without `--target-dir`, storage is unchecked and `ready` is false (exit 2). Unknown, duplicate and missing options are rejected (exit 1).

The source check uses acquisition's own ELF/direct-map/RAM/symbol validation and a sample PFN read. It tests actual access rather than equating UID 0 with sufficient privilege. `/proc/kcore`, `/proc/kpageflags`, readable unmasked required symbols and the relevant host proc/sys interfaces remain prerequisites. Missing `CONFIG_PROC_KCORE` is an accepted unsupported environment. The tool does not change sysctls, lockdown, LSM, Secure Boot or capability settings.

The capacity gate matches capture: at least max(10% of reported System RAM, 1 GiB) available. It is a minimum gate, **not space reservation or a bound on dump size**. A passing check describes that instant only; later storage exhaustion, access changes or I/O errors still fail capture. Use persistent Linux storage supporting private ownership/modes, exclusive creation, `renameat2(RENAME_NOREPLACE)` and file/directory fsync. WSL Windows shared storage is rejected where it does not preserve private modes. Local ext4 was exercised; network storage is not qualified. tmpfs tests do not establish persistence across reboot.

## Qualification and remaining limits

The identical binary captured and verified on the Ubuntu VM, WSL2 ext4, Debian 12/13, Rocky Linux 8/9 and Kali cloud images listed in the [README](../README.md#tested-environments). The [additional VM matrix](distro_validation.md) records exact kernels, ext4/XFS and security contexts. Both Alpine kernels executed the binary but lacked kcore, so acquisition was refused. ARM64, every cloud kernel and every security policy remain outside this qualification.

Exit 0 means complete acquisition **for the recorded PFN policy** and successful final persistence; exit 2 means incomplete capture or failed readiness; exit 1 means command/setup/verification/persistence error. Preserve stderr and fragments. SIGKILL can prevent a final manifest. Cancellation is cooperative; a blocked kernel I/O call can outlast a deadline. Collection is non-atomic and is neither entire RAM nor a strict guarantee of kernel-only data. Keep host-level capture scheduling bounded; the PodDump admission mechanism does not serialize independent KernelDump requests.

## Build identity and rebuilding

Cargo's `build.rs` generates source SHA-256 values, a vendored-tree digest, actual features, target and compiler on build. `--build-info` and capture manifests add `runtime_executable_sha256` from `/proc/self/exe`; no self-referential binary hash is embedded. `release/manifest.json` independently records the final executable hash. Neither file is needed at runtime. Rehash modified or stripped artifacts.

With Rust 1.90.0 plus the `x86_64-unknown-linux-musl` standard library installed, run `python3 scripts/build_release.py`. It builds/tests offline, verifies a standalone production ELF and source hashes, and writes the binary and receipt. Python is a build-host dependency only. Use generic x86-64 CPU flags for distribution.

Earlier performance and analysis tables remain historical evidence. The 2026-10-17 work fixes deployment defects and validates stability; it does not rerun or extend those performance/analysis claims.
