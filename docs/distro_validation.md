# Additional distribution validation — 2026-10-17

The unchanged PodDump 0.3.1 and KernelDump 0.1.1 release executables were copied into five independently booted, official x86-64 cloud images. Each VM used its own supplied kernel and default kernel security policy, two virtual CPUs and 2 GiB RAM. Cloud-init added a disposable SSH administration account for the tests. QEMU TCG was used; these are compatibility results, not performance measurements.

| Environment | Kernel | Storage / cgroup | Result |
|---|---|---|---|
| Debian 12 | 6.1.0-53-cloud-amd64 | ext4 / v2 | Both tools captured and verified |
| Debian 13 | 6.12.111+deb13-cloud-amd64 | ext4 / v2 | Both tools captured and verified |
| Rocky Linux 8.10 | 4.18.0-553.el8_10.x86_64 | xfs / v1 | Both tools captured and verified |
| Rocky Linux 9.8 | 5.14.0-687.10.1.el9_8.0.1.x86_64 | xfs / v2 | Both tools captured and verified |
| Kali Rolling (cloud 2026.2) | 6.18.12+kali-cloud-amd64 | ext4 / v2 | Both tools captured and verified |

The official Kali archive is labelled 2026.2, while its `/etc/os-release` reports `VERSION_ID=2026.1`. The row identifies that specific cloud artifact and its recorded 6.18.12 kernel.
PodDump captured a four-thread fixture with a known 16-MiB memory pattern in each of three synthetic cgroup path layouts: containerd, CRI-O and Docker. All 15 ELF cores passed structural and full-pattern checks (240 MiB total), and every target was untraced and running after capture. These tests do not install those runtimes or establish Kubernetes integration on every distribution; the previous Ubuntu Kubernetes/containerd test remains the actual runtime integration case.

KernelDump passed readiness, capture and its verifier in all five VMs. An independent parser also checked LiME headers, increasing physical ranges, payload lengths and manifest accounting. All 20 capture manifests identified the expected executable hashes. The 75 CLI invocations include version/build identity, successful captures, verification, invalid input, existing-output protection and non-root/read-only refusal; they are not 75 successful captures.

The Rocky cases kept SELinux enforcing and ran from an unconfined administrative login through sudo. This does not certify every confined service domain or SELinux policy. No kptr/ptrace sysctl, lockdown setting or LSM enforcement setting was relaxed. The images used their supplied kernels without package upgrades; the recorded versions define the test boundary. ARM64, Secure Boot/lockdown restrictions, arbitrary network filesystems and long-running service impact are outside this additional smoke test.

The first Windows WHPX boot attempt failed before the collectors ran; the retained receipt records that host virtualization failure. TCG boots completed normally. Downloaded base images, derived disks, overlays, seed media and disposable SSH keys are cleaned up after evidence export; image URLs/checksums, console logs, capture evidence and file-hash receipts remain in the experiment record. Existing VMs are not removed.

Exact versions, source image URLs and hashes: [distro_validation.json](distro_validation.json). Experiment: `collector_distro_matrix_20261017`. This extends the earlier [release validation](release_validation.md); collector code, binary hashes and the historical benchmark tables are unchanged.
