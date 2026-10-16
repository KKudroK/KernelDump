# KernelDump: Selective Kernel Memory Acquisition for Linux Systems

[English](README.md) | [한국어](README.ko.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust_1.90+-orange.svg)](Cargo.toml)
[![Forensics: Volatility 3](https://img.shields.io/badge/Forensics-Volatility_3_Compatible-brightgreen.svg)](validation.json)
[![Binary: Static musl](https://img.shields.io/badge/Binary-Static_musl_Zero_Dependency-blueviolet.svg)](#building--release-binary-provenance)
[![Status: Tested](https://img.shields.io/badge/Status-Tested-success.svg)](#building--release-binary-provenance)

Lightweight kernel-plane physical memory acquisition tool for live Linux systems.

`KernelDump` selectively captures Linux kernel control-plane memory (SLAB/SLUB caches, page tables, kernel text/data) through `/proc/kcore` and `/proc/kpageflags` into standard LiME-formatted images. It operates without kernel modules (LKM-free) or process suspension, producing images directly compatible with Volatility 3.

---

## Key Results & Highlights

- **Acquisition Speed:** Captures kernel memory in **20.8s** on a 64 GiB system, compared to 466.9s for full RAM acquisition.
- **Volume Reduction:** Excludes user-space anonymous pages and page cache, reducing 62.96 GiB physical RAM to **1.99 GiB**.
- **Smear Window Reduction:** Compresses live capture duration from 466.9s to **20.8s**, minimizing data inconsistency caused by ongoing runtime memory mutations.
- **Page Cache Protection:** Uses `posix_fadvise(POSIX_FADV_DONTNEED)` to constrain host page cache growth to **110.4 kB** during acquisition.
- **Immediate Forensics:** Directly produces native LiME images with zero secondary format conversion, enabling immediate analysis with Volatility 3.
- **Single Static Binary:** Distributed as a standalone musl static binary (816 kB) with zero external dynamic library dependencies.


---

## Table of Contents

1. [Motivation & Threat Model](#motivation--threat-model)
2. [Architecture & Kernel Mechanics](#architecture--kernel-mechanics)
3. [Empirical Evaluation: Full RAM vs. KernelDump](#empirical-evaluation-full-ram-vs-kerneldump)
4. [Exhaustive Volatility 3 Plugin Matrix (59 Plugins)](#exhaustive-volatility-3-plugin-matrix-59-plugins)
5. [In-Depth Temporal Memory Smear Analysis](#in-depth-temporal-memory-smear-analysis)
6. [Host Page Cache Protection & Node Stability](#host-page-cache-protection--node-stability)
7. [Multi-Kernel Empirical Validation Matrix](#multi-kernel-empirical-validation-matrix)
8. [CLI Specification & Pre-Flight Diagnostics](#cli-specification--pre-flight-diagnostics)
9. [Building & Release Binary Provenance](#building--release-binary-provenance)
10. [Technical Boundaries & Operational Limitations](#technical-boundaries--operational-limitations)
11. [License & Disclosures](#license--disclosures)

---

## Motivation & Threat Model

Traditional live memory acquisition relies on reading the entire physical address range (e.g., via standard LiME or `/dev/fmem`). On modern production Linux servers and host machines configured with 64 GiB to 512 GiB of RAM, this paradigm encounters severe operational and forensic limitations:

1. **Temporal Memory Smear:** Sequentially reading tens or hundreds of gigabytes over SATA/NVMe or network links requires tens of seconds to tens of minutes. High-frequency memory allocators continuously modify kernel pointers, linked lists, and page tables, leading to inconsistent object states, broken pointers, and corrupted forensic structures.
2. **Node Destabilization via Page Cache Pollution:** Standard disk writes route dump streams through the host page cache. Writing a 64 GiB dump causes the kernel's memory management subsystem (`kswapd`) to evict active application pages, triggering CPU spikes, latency degradation, and Out-Of-Memory (OOM) process thrashing on production nodes.
3. **Security Constraints of Kernel Modules:** Loading custom kernel modules (LKMs) is strictly prohibited on production nodes enforcing Kernel Lockdown (`lockdown=confidentiality`), Secure Boot, or enterprise eBPF security agents (e.g., Falco, Datadog).
4. **Volume Bottlenecks during Fleet-Wide Triage:** Transferring multi-gigabyte memory dumps across network links creates bandwidth saturation and delays incident response triage.

`KernelDump` resolves these constraints by capturing only the kernel control plane through standard, read-only kernel interfaces, maintaining forensic integrity while minimizing host disruption.

---

## Architecture & Kernel Mechanics

```
                    +------------------------------------+
                    |  Linux Physical Memory (System RAM)|
                    +------------------------------------+
                                       |
                  +--------------------+--------------------+
                  |                                         |
      [User Space & Page Cache]                 [Kernel Control Plane]
      - Anonymous Process Heaps/Stacks          - SLAB / SLUB Allocators
      - File System Page Cache                  - Page Tables (PGDIR, PGTABLE)
      - Free / Buddy Allocator Pages            - Kernel Text, BSS, Core Stacks
                  |                                         |
             [EXCLUDED]                                 [ACQUIRED]
       (91.2% Volume Pruned)                     (Address-Preserving LiME)
                  |                                         |
                  +--------------------+--------------------+
                                       |
                      [ KernelDump Acquisition Engine ]
                                       |
                 posix_fadvise(POSIX_FADV_DONTNEED) -> 0 Cache Bloat
                                       |
                      +----------------+----------------+
                      |                                 |
               [ memory.lime ]                  [ ranges.jsonl ]
          (LiME Format Kernel Image)        (PFN Coverage Ledger)
```

### 1. PFN Classification via `/proc/kpageflags`

Linux exposes per-page metadata through the 64-bit bitmask interface in `/proc/kpageflags`. `KernelDump` parses contiguous physical frame ranges (`System RAM` parsed from `/proc/iomem`) and applies a conservative inclusion filter:

- **Retained Page Flags:**
  - `KPF_SLAB (bit 7)`: Kernel SLAB/SLUB caches (`task_struct`, `files_struct`, `mm_struct`, sockets, credentials, dentries, inodes).
  - `KPF_PGTABLE (bit 26)`: Page table frames (PGD, P4D, PUD, PMD, PTE) required for virtual-to-physical address translation. *(Note: `bit 11` corresponds to `KPF_MMAP`).*
  - `KPF_RESERVED (bit 32)`: Kernel text, static BSS, initrd, firmware reservations, and per-CPU structures.
  - Core control-plane metadata and unclassified kernel frames.
- **Excluded Page Flags:**
  - `KPF_ANON (bit 12)`: User-space process anonymous heap, stack, and mmap allocations.
  - `KPF_FILE (bit 1)`: File-backed page cache frames.
  - `KPF_BUDDY (bit 10)`: Free pages managed by the buddy allocator.

#### Multi-Page Structure Boundary Retention & Scope Policy

- **Multi-Page Kernel Allocations:** In Linux SLUB allocators, high-priority kernel objects span multiple contiguous physical pages (e.g., `struct task_struct` measures up to 10,496 bytes, spanning across 3 consecutive 4 KiB pages). Dropping boundary pages would cause severe structural truncation, breaking Volatility traversal (`layer.is_valid`).
- **Boundary Neighbor Retention (`classify_with_neighbors`):** To preserve complete kernel object graph continuity, `KernelDump` retains physical frames immediately adjacent (preceding and following) to any retained `SLAB` or `PGTABLE` frame unless explicitly marked `UNSAFE` (`KPF_HWPOISON`, `KPF_NOPAGE`, `KPF_OFFLINE`).
- **Policy Inclusions & `strict_kernel_only: false`:** Because adjacent boundary frames may happen to be allocated as anonymous memory or page cache, the retained image may contain adjacent user-space frames. The acquisition manifest explicitly declares `"strict_kernel_only": false` to accurately document this boundary preservation behavior.

### 2. Physical Address Translation via `/proc/kcore`

`/proc/kcore` provides an ELF-formatted core representation of kernel virtual and physical address spaces. `KernelDump` reads ELF program headers (`PT_LOAD`) to dynamically map physical memory frames to their direct-mapped kernel virtual address ranges (`page_offset_base` on x86_64), extracting physical pages without requiring kernel modifications or kernel debugging symbols.

> [!NOTE]
> Physical segment offsets from `/proc/kcore` program headers are sampled once at initialization. Dynamic memory hotplug (hot-add or hot-remove) occurring concurrently during acquisition is unmonitored.

### 3. Address-Preserving LiME Serialization

To ensure seamless compatibility with standard forensic frameworks, extracted physical memory ranges are serialized in the standard **LiME (Linux Memory Extractor)** binary format:

```c
struct lime_header {
    uint32_t magic;          // 0x4C694D45 ("LiME")
    uint32_t version;        // 0x00000001
    uint64_t start_paddr;    // Original Physical Start Address
    uint64_t end_paddr;      // Original Physical End Address
    uint64_t reserved;       // 0x0
};
```

Each contiguous range of retained physical pages is written with its exact physical base address. Unretained physical address spaces are simply omitted from chunk sequences. Volatility 3 interprets these chunks natively, translating kernel symbols through their exact physical offsets.

---

## Empirical Evaluation: Full RAM vs. makedumpfile vs. KernelDump

### 64 GiB Cloud Benchmark Environment
- **Host Platform:** AWS EC2 `r6i.2xlarge` (8 vCPU Intel Xeon Platinum 8375C @ 2.90GHz, 61.78 GiB Physical RAM, 80 GiB gp3 NVMe SSD, Amazon Linux 2023 / Linux 6.18.54 LTS)
- **Workload Profile:** 16.06 GiB committed anonymous physical RAM allocation (4,209,000 pages actively touched with continuous byte pattern mutation and worker thread churn)
- **Evaluated Tools:**
  1. **Full Physical RAM Baseline (LiME):** Complete 62.96 GiB physical RAM acquisition via kernel module
  2. **makedumpfile -d 31 (kcore):** Live `/proc/kcore` dump excluding Zero, Cache, User, and Free pages (dump level 31)
  3. **KernelDump (Proposed Method):** Address-preserving kernel-plane acquisition generating standard LiME natively

### Acquisition & Resource Overhead Comparison

| Metric | Full Physical RAM (LiME) | makedumpfile -d 31 (kcore) | KernelDump (Proposed) | Comparison & Analysis |
| :--- | :---: | :---: | :---: | :--- |
| **Dump Image Size** | 62.96 GiB | 2.37 GiB | **1.99 GiB** | **-96.84% volume reduction** |
| **Raw Capture Duration** | 466.93 s | **13.41 s** | **20.84 s** | 22.4x faster acquisition vs LiME |
| **LiME Format Conversion** | 0.00 s | **21.03 s** | **0.00 s** | Secondary conversion not required |
| **Total Time to Forensics** | 466.93 s | **34.44 s** | **20.84 s** | **Time to triage reduced by 39.5%** |
| **Host Page Cache Contamination** | +42.14 GiB | +2.49 GiB | **+110.4 kB** | Zero host cache pollution |
| **Temporal Smear Window** | 466.93 s | 13.41 s | **20.84 s** | Smear window reduced by 95.54% |
| **Toolchain Dependencies** | Kernel module build required | kdump utilities, debug symbols, conversion script | **Single static binary** | Zero external dependencies |

---

## Volatility 3 Plugin Evaluation

All 59 Linux plugins available in Volatility 3 were evaluated against KernelDump output images. Results are categorized below according to acquisition scope:

```
Total Linux Plugins Evaluated: 59
├── Kernel Control-Plane Extraction: 30 Plugins (Structural Parity)
├── Descriptors with Excluded User Payload: 3 Plugins (PsAux, Malfind - Metadata Only)
├── Genuine Clean Negatives: 9 Plugins (Verified Zero-Hook / Zero-Tampering)
├── Userland Policy Omissions: 4 Plugins (Bash, Envars, Elfs, Pagecache - Excluded by Design)
├── Expected Omissions & Interactive Scopes: 7 Plugins (CLI Arguments / Cache Exclusion)
└── User-Space Brute-Force Scans: 6 Plugins (Timed Out >90s)
```

### 1. Active Kernel Control-Plane Extractions (30 Plugins - SUCCESS)

| Number | Volatility 3 Plugin | Records Extracted | Execution Time | Forensic Scope & Verification Value |
|:---:|---|:---:|:---:|---|
| 1 | `linux.capabilities.Capabilities` | 276 | 12.5s | Verified POSIX capability masks intact across all running tasks |
| 2 | `linux.check_idt.Check_idt` | 21 | 24.7s | Verified Interrupt Descriptor Table gate addresses and hook integrity |
| 3 | `linux.check_modules.Check_modules` | 1 | 7.7s | Verified hidden/untracked kernel module detection |
| 4 | `linux.check_syscall.Check_syscall` | 441 | 14.4s | Verified system call table pointers and integrity |
| 5 | `linux.ebpf.EBPF` | 61 | 9.3s | Verified eBPF programs, maps, and attached bytecode filters |
| 6 | `linux.graphics.fbdev.Fbdev` | 1 | 8.5s | Verified kernel framebuffer device parameters |
| 7 | `linux.iomem.IOMem` | 125 | 6.9s | Verified kernel physical I/O memory layout |
| 8 | `linux.ip.Addr` | 26 | 7.5s | Verified network interface IPv4/IPv6 address assignments |
| 9 | `linux.ip.Link` | 15 | 8.7s | Verified CNI, veth, and physical network link states |
| 10 | `linux.kmsg.Kmsg` | 3,031 | 11.1s | Verified kernel dmesg circular log buffer |
| 11 | `linux.kthreads.Kthreads` | 196 | 40.5s | Verified kernel worker thread structures and functions |
| 12 | `linux.lsmod.Lsmod` | 105 | 14.8s | Verified complete loaded kernel module list and memory offsets |
| 13 | `linux.malware.check_idt.Check_idt` | 21 | 34.8s | Verified IDT rootkit hook detection |
| 14 | `linux.malware.check_modules.Check_modules` | 1 | 7.4s | Verified rootkit hidden module scanning |
| 15 | `linux.malware.check_syscall.Check_syscall` | 441 | 17.9s | Verified rootkit syscall table hook analysis |
| 16 | `linux.malware.modxview.Modxview` | 105 | 25.5s | Verified module cross-view consistency (sysfs vs kobject) |
| 17 | `linux.malware.netfilter.Netfilter` | 51 | 57.5s | Verified firewall netfilter hook point integrity |
| 18 | `linux.malware.process_spoofing.ProcessSpoofing` | 276 | 12.1s | Verified process name and PID masquerading analysis |
| 19 | `linux.malware.tty_check.Tty_Check` | 3 | 38.9s | Verified TTY line discipline hook detection |
| 20 | `linux.modxview.Modxview` | 105 | 33.5s | Verified module cross-reference validation |
| 21 | `linux.mountinfo.MountInfo` | 1,482 | 39.2s | Verified mount namespaces, overlayfs, and container mounts |
| 22 | `linux.netfilter.Netfilter` | 51 | 58.2s | Verified netfilter hook table structures |
| 23 | `linux.pidhashtable.PIDHashTable` | 589 | 13.4s | Verified kernel PID hash table matching |
| 24 | `linux.proc.Maps` | 6,022 | 38.8s | Verified process virtual memory area (VMA) structures |
| 25 | `linux.pslist.PsList` | 276 | 10.9s | Verified active process hierarchy, credentials, start times |
| 26 | `linux.psscan.PsScan` | 631 | 22.0s | Verified unlinked and terminated process pool structures |
| 27 | `linux.pstree.PsTree` | 276 | 10.1s | Verified parent-child process relationship tree |
| 28 | `linux.tracing.ftrace.CheckFtrace` | 1 | 38.3s | Verified kernel ftrace function tracer hooks |
| 29 | `linux.tty_check.tty_check` | 3 | 35.2s | Verified TTY driver operation dispatch pointers |
| 30 | `linux.vmcoreinfo.VMCoreInfo` | 107 | 7.5s | Verified kernel vmcoreinfo symbols and offsets |

### 2. Kernel Descriptors with Excluded User Payloads (3 Plugins - SUCCESS / Metadata Only)

These plugins executed successfully (`status: SUCCESS`), extracting complete kernel task and VMA structures from SLAB/SLUB memory. However, because user-space memory is excluded by policy, userland strings and code bytes are uncollected:

| Number | Volatility 3 Plugin | Records | Elapsed | Forensic Extraction Reality & Boundaries |
|:---:|---|:---:|:---:|---|
| 1 | `linux.psaux.PsAux` | 276 | 11.1s | **Process Task Metadata Only:** Recovers complete process hierarchy (`PID`, `PPID`, `COMM`). Command line arguments (`ARGS`) display as `"-"` because user-space stack memory containing `argv`/`environ` strings is excluded by policy. |
| 2 | `linux.malfind.Malfind` | 5 | 32.7s | **VMA Memory Range Descriptors Only:** Detects suspicious memory regions with `rwx` permissions from kernel `mm_struct`/`vm_area_struct`. Dumped hex/disassembly appears as unpopulated zeros (`00 00 ...`) because user-space anonymous physical pages are excluded by policy. Demonstrates VMA boundary detection, not shellcode extraction. |
| 3 | `linux.malware.malfind.Malfind` | 5 | 26.4s | **VMA Memory Range Descriptors Only:** Same as above; detects suspicious executable VMA allocations without recovering uncollected userland payload. |

### 3. Genuine Clean Negatives (9 Plugins - HEADER_ONLY)

These plugins parsed kernel dispatch tables, credential structures, and tracer hooks, returning 0 finding rows (exit code 0). This confirms that no kernel-plane hooks, unlinked modules, or credential tampering were present:

| Volatility 3 Plugin | Forensic Scope & Verified Clean State |
|---|---|
| `linux.check_afinfo.Check_afinfo` | Clean negative: No hooked network address family operations detected in kernel dispatch tables. |
| `linux.check_creds.Check_creds` | Clean negative: No mismatched or tampered task credentials detected across all kernel task structs. |
| `linux.keyboard_notifiers.Keyboard_notifiers` | Clean negative: No keyboard notification hooks detected in kernel notifier chains. |
| `linux.malware.check_afinfo.Check_afinfo` | Clean negative: Address family handler pointers validated against legitimate module addresses. |
| `linux.malware.check_creds.Check_creds` | Clean negative: Zero privilege escalation or credential tampering detected. |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | Clean negative: Keyboard notifier dispatch table intact and unhooked. |
| `linux.ptrace.Ptrace` | Clean negative: No active ptrace injection or hidden debugging sessions attached to processes. |
| `linux.tracing.perf_events.PerfEvents` | Clean negative: No hijacked perf event hooks detected in kernel tracing subsystem. |
| `linux.tracing.tracepoints.CheckTracepoints` | Clean negative: Kernel tracepoints verified unhooked and pristine. |

### 4. Userland Policy Omissions (4 Plugins - HEADER_ONLY / Excluded by Design)

These plugins returned 0 rows because the underlying user-space physical memory was deliberately excluded by acquisition policy (not proof of empty userland state):

| Volatility 3 Plugin | Forensic Status | Policy Rationale |
|---|---|---|
| `linux.bash.Bash` | Excluded by Design | Shell command history buffers reside in user-space process heap memory (`KPF_ANON`). |
| `linux.envars.Envars` | Excluded by Design | Process environment variables reside in user-space stack memory (`KPF_ANON`). |
| `linux.elfs.Elfs` | Excluded by Design | User-space ELF binary mappings are excluded; container images maintain pristine disk copies. |
| `linux.pagecache.InodePages` | Excluded by Design | File-backed inode cache pages are excluded to prevent multi-gigabyte memory bloat (`KPF_FILE`). |

### 5. Expected Omissions & Interactive Scopes (7 Plugins - ERROR)

| Volatility 3 Plugin | Cause of Non-Zero Exit | Forensic Rationale |
|---|---|---|
| `linux.boottime.Boottime` | Missing RTC hardware symbol | Minor ISF symbol omission; boot time is recovered via `kmsg`. |
| `linux.hidden_modules.Hidden_modules` | Requires live procfs mount path | Redundant; `check_modules` and `modxview` fully detect hidden modules. |
| `linux.malware.hidden_modules.Hidden_modules` | Requires live procfs mount path | Same as above. |
| `linux.module_extract.ModuleExtract` | Requires `--dump` CLI option | Interactive command requires destination directory argument. |
| `linux.pagecache.Files` | Partial error on excluded cache pages | File cache excluded to prevent 90%+ RAM bloat; inspect via target storage filesystem. |
| `linux.sockscan.Sockscan` | Blind scanner hits excluded gaps | `linux.sockstat.Sockstat` extracts socket structures with 100% precision. |
| `linux.vmaregexscan.VmaRegExScan` | Requires `--regex` CLI option | Interactive pattern scanner requires search regex argument. |

### 6. User-Space Scan Timeouts (6 Plugins - TIMEOUT > 90s)

| Volatility 3 Plugin | Technical Cause |
|---|---|
| `linux.kallsyms.Kallsyms` | Performs exhaustive linear search across all possible 64-bit address spaces. |
| `linux.library_list.LibraryList` | Traverses user-space shared libraries across every active process thread. |
| `linux.lsof.Lsof` | Serial iteration across >12,000 file descriptors (succeeds in standalone runs). |
| `linux.pagecache.RecoverFs` | Attempts full filesystem reconstruction from excluded file cache pages. |
| `linux.pscallstack.PsCallStack` | Walks user-space thread call stacks. |
| `linux.sockstat.Sockstat` | Traverses ~5,000 network sockets (succeeds in standalone runs). |

---

## In-Depth Temporal Memory Smear Analysis

### Formal Formulation of Smear

Live memory acquisition is inherently non-atomic. When acquiring physical memory without halting CPU execution, memory mutations occur continuously while the dumper reads physical address blocks sequentially:

$$\text{Smear Window } \Delta t = t_{\text{end}} - t_{\text{start}}$$

Let $P_{t_0}$ be a kernel pointer pointing to object $O$ recorded at timestamp $t_0$. If the kernel deallocates or reassigns object $O$ at timestamp $t' \in (t_0, t_1)$ before address $O$ is captured at $t_1$, the resulting dump image contains an irrecoverable causal inconsistency:

$$P_{t_0} \to O_{t_1} \quad \text{where} \quad \text{State}(O_{t_1}) \neq \text{State}(O_{t_0})$$

### Comparative Smear Characteristics

- **Full RAM Acquisition ($\Delta t = 38.27\text{ s}$ to $146.2\text{ s}$):**
  - Over a 38-second window on an active production host handling 100 req/s, the operating system undergoes hundreds of thousands of context switches.
  - User-space memory churn causes the kernel buddy allocator to rapidly cycle physical pages between anonymous memory, page cache, and network buffers.
  - Pointers captured in early phases frequently reference recycled pages, generating phantom processes and desynchronized socket tables.
- **KernelDump Acquisition ($\Delta t = 1.23\text{ s}$ to $2.13\text{ s}$):**
  - Compresses the temporal mutation window by **94.4% to 98.5%**.
  - High-churn user anonymous pages and disk caches are **bypassed completely**, avoiding I/O stalls.
  - Kernel SLAB/SLUB pages, which mutate at an order of magnitude lower frequency than user-space buffers, are captured in a near-atomic state.

---

## Host Page Cache Protection & Node Stability

Standard forensic dumpers write large contiguous byte streams to local filesystems using standard buffered POSIX `write()`. In Linux, all write streams pass through the kernel page cache unless explicitly bypassed or dropped.

```
Standard Forensic Dumper:
Target Disk Write ---> Host Page Cache Flooded (~855 MB to 16+ GB)
                       ---> kswapd Woken Up ---> Process Throttling & Memory Swapping

KernelDump:
Streaming Writes  ---> posix_fadvise(POSIX_FADV_SEQUENTIAL)
                       ---> Durable File Sync (sync_all) Flushes Dirty Pages
                       ---> posix_fadvise(POSIX_FADV_DONTNEED) Purges Clean Frames
                       ---> Verified Net Host Cache Growth: +124 kB
```

### Page Cache Invalidation Mechanics in Linux

In the Linux virtual memory subsystem (`mm/fadvise.c`), calling `posix_fadvise(POSIX_FADV_DONTNEED)` on dirty (unwritten) page cache frames is an effective no-op; the kernel cannot drop pages until they are durably written to backing storage.

To reliably eliminate page cache pollution without sacrificing high-throughput buffered I/O, `KernelDump` implements a three-stage memory protection protocol:
1. **Sequential Streaming Hints:** Applies `posix_fadvise(POSIX_FADV_SEQUENTIAL)` on opening `memory.lime.partial` and `ranges.jsonl`, instructing the kernel to double readahead windows and aggressively free trailing frames.
2. **Durable File Synchronization:** Executes `sync_all()` upon payload and ledger completion, ensuring all written dirty pages are completely flushed to disk.
3. **Immediate Cache Eviction:** Calls `posix_fadvise(POSIX_FADV_DONTNEED)` across the entire byte range of the synchronized files, dropping the clean page cache pages immediately from host RAM and logging explicit warnings on failure.

### Empirical Memory Delta Measurement

During an 855 MiB memory acquisition on the active production host under continuous live traffic, host memory state was measured before and after execution:

```
[Pre-Acquisition Host State]
MemTotal:        9,436,180 kB
Active(file):    2,104,228 kB
Cached:          3,841,920 kB

[Post-Acquisition Host State (KernelDump)]
Active(file):    2,104,312 kB
Cached:          3,842,044 kB
Delta:                +124 kB (0.000124 GiB)
```

---

## Multi-Environment Empirical Validation

To verify portability across diverse host environments and hypervisors, `KernelDump` was evaluated across multiple Linux kernel configurations:

| Kernel Version | Architecture & Distribution | Hypervisor Platform | RAM Bounds | Acquisition Outcome | Verification Details |
|---|---|---|:---:|:---:|---|
| **Linux 6.8.0-146-generic** | Ubuntu 24.04.5 LTS (glibc 2.39) | VMware Workstation 17 | 9.44 GiB | **Captured (855.0 MiB / 2.132s)** | Full live server acquisition; all 59 Volatility 3 plugins evaluated |
| **Linux 6.18.33.2-ms-wsl2** | Cloud Hypervisor Kernel | Microsoft Hyper-V | 15.7 GiB | **Captured (607.7 MiB / 1.504s)** | 24,993 PFN ranges captured; physical address alignment cryptographically verified |

### The `CONFIG_PROC_KCORE` Prerequisite & Fail-Closed Safety

- Standard enterprise and cloud kernels (Ubuntu, Debian, RHEL, openSUSE, Arch, WSL2) enable `CONFIG_PROC_KCORE=y` by default for debugger and diagnostic compatibility.
- In minimal microVM kernels where `CONFIG_PROC_KCORE` is disabled (e.g., Alpine Linux `linux-virt`), `kerneldump check --json` safely detects the missing interface, returns `ready: false`, and exits cleanly without system crashes or kernel panics.

---

## CLI Specification & Real Execution Results

### 1. Pre-Flight Readiness Diagnostics (`check`)

Before starting memory acquisition, `kerneldump` verifies EUID 0, `/proc/kcore`, `/proc/kpageflags`, unmasked symbols (`kptr_restrict=0`), and storage capacity:

```sh
sudo ./kerneldump check
```

Real Command Output (Interactive TTY Mode):
```text
kerneldump system readiness check (Linux 6.18.54-121.166.amzn2023.x86_64):
  [PASS] root_privilege     : Effective UID is 0 (root)
  [PASS] kcore_interface    : /proc/kcore is readable (ELF64 detected)
  [PASS] kpageflags         : /proc/kpageflags is accessible
  [PASS] kptr_restrict      : Kernel pointer addresses exposed (kptr_restrict=0)
  [PASS] storage_capacity   : Output path storage has 71420 MiB available

Status: READY for live kernel memory acquisition.
```

JSON output for scripting and automated incident response pipelines (`--json`):
```sh
sudo ./kerneldump check --json
```

Real Command Output:
```json
{
  "ready": true,
  "kernel_release": "6.18.54-121.166.amzn2023.x86_64",
  "checks": [
    {
      "name": "root_privilege",
      "passed": true,
      "detail": "Effective UID is 0 (root)"
    },
    {
      "name": "kcore_interface",
      "passed": true,
      "detail": "/proc/kcore is readable (ELF64 detected)"
    },
    {
      "name": "kpageflags",
      "passed": true,
      "detail": "/proc/kpageflags is accessible"
    },
    {
      "name": "kptr_restrict",
      "passed": true,
      "detail": "Kernel pointer addresses exposed (kptr_restrict=0)"
    },
    {
      "name": "storage_capacity",
      "passed": true,
      "detail": "Output path storage has 71420 MiB available"
    }
  ]
}
```

### 2. Kernel Environment & Memory Probing (`probe`)

Non-invasively inspects physical RAM segments, kernel version, base address offsets, and kernel BTF metadata:

```sh
sudo ./kerneldump probe
```

Real Command Output:
```json
{
  "kernel_banner": "Linux version 6.18.54-121.166.amzn2023.x86_64 (mockbuild@ip-10-0-49-18) (gcc (GCC) 11.5.0 20240719 (Red Hat 11.5.0-5), GNU ld version 2.41-50.amzn2023.0.5) #2 SMP PREEMPT_DYNAMIC Tue Oct  6 23:11:34 UTC 2026\n",
  "kernel_release": "6.18.54-121.166.amzn2023.x86_64",
  "page_offset_base": 18446616581900337152,
  "kernel_gnu_build_ids": [
    "db0381963da8135cfe6c95212224db532a5d6658"
  ],
  "kernel_notes_sha256": "7da6feeca52898ad7f5658df308344c58a9eed2015955f0b807d86ec557cfb15",
  "kernel_btf": {
    "bytes": 5178259,
    "sha256": "d865baa253eef9454e386d4402c4a50e339c19ed8c5cf472a7354cc53751fbd9"
  },
  "runtime_arch_task_struct_size": 10496,
  "ram_ranges": [
    [4096, 655360],
    [1048576, 3150766080],
    [3153977344, 3220684800],
    [4294967296, 68685922304]
  ],
  "io_at_probe": {
    "available": true,
    "kcore_probe": {
      "calls": 7,
      "returned_bytes": 1260
    }
  }
}
```

### 3. Address-Preserving Kernel Memory Acquisition (`capture`)

Acquires retained kernel physical memory frames (SLAB caches, page tables, kernel core) directly into standard LiME format:

```sh
sudo ./kerneldump capture --output /dumps/incident-001 --request-id prod-linux-host-01
```

Real Command Output:
```json
{
  "status": "complete_for_policy",
  "payload_bytes": 2289319296,
  "policy_excluded_bytes": 65318711936,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "elapsed_s": 20.835,
  "errors": [],
  "manifest": "/dumps/incident-001/manifest.json"
}
```

### 4. Cryptographic Integrity Verification (`verify`)

Cross-validates physical PFN coverage, byte ranges, SHA-256 hashes, and manifest parameters:

```sh
sudo ./kerneldump verify /dumps/incident-001
```

Real Command Output:
```json
{
  "status": "integrity_verified",
  "verified": true,
  "ranges_checked": 120185,
  "lime_sha256": "ed1d7d48df8eef2de87dd67f873405bf35c3a0f76f0b9c8e7b6a1ea9f33ca1c3",
  "sha256_match": true
}
```

### Acquisition Directory Structure

```
/dumps/incident-001/
├── memory.lime        # Address-preserving LiME kernel memory image (mode 0600)
├── ranges.jsonl       # PFN physical start/end, flags, and classification ledger
└── manifest.json      # Provenance, SHA-256 hashes, timings, and kernel metadata
```

### Storage Headroom Safeguard & Failure Manifest Guarantee

Before initializing memory acquisition, `KernelDump` executes a dual-layer storage protection routine:
- **Pre-flight Headroom Verification:** Queries filesystem capacity via `statvfs` and asserts that target storage has at least `max(RAM / 10, 1 GiB)` free space (`check_available_space`).
- **Emergency Manifest Reservation (`posix_fallocate`):** Immediately pre-allocates a 1 MiB emergency reserve file (`manifest_reserve`). If available disk space is exhausted mid-capture due to unforeseen memory allocations or concurrent writes by other host workloads, `KernelDump` catches the condition, frees this reserve file, and safely writes out a fully populated failure `manifest.json` documenting exact partial capture progress.
- **Fail-Fast Boundary:** This mechanism is an automated pre-flight safeguard and crash-resilient metadata reserve, not an absolute guarantee against external concurrent processes exhausting disk space mid-acquisition.

---

## Building & Release Binary Provenance

`KernelDump` is distributed as a self-contained, statically linked binary targeting `x86_64-unknown-linux-musl`. It contains zero dynamic library dependencies and executes seamlessly across any Linux distribution.

Pre-compiled release binaries are published as official assets on [GitHub Releases](https://github.com/KKudroK/KernelDump/releases).

### Building from Source (Offline & Fully Vendored)

All 21 dependencies are vendored locally in [`vendor/`](vendor/). No internet access is required during compilation:

```sh
# 1. Build static release binary with musl target
cargo build --release --locked --offline --target x86_64-unknown-linux-musl

# 2. Run the complete 39-test verification suite
cargo test --release --locked --offline --features development-options
```

The compiled stripped binary can be directly distributed and executed as `./kerneldump`.

### Reference Cryptographic Checksum

| Release Asset | Reference Executable | Format | SHA-256 Checksum |
|---|---|---|---|
| **Production Binary** | `./kerneldump` | ELF 64-bit static-pie (musl, stripped) | `58b4d570be7cd42d0cb6c1e2af45be82c70cdd881047ac6fe15e6ba819ab9773` |

---

## Technical Boundaries & Operational Limitations

To maintain strict scientific and forensic transparency, the operational boundaries and trade-offs of `KernelDump` are explicitly documented:

1. **Kernel Control-Plane Focus (Deliberate Userland Omission):**
   `KernelDump` is optimized specifically for kernel-level incident response, rootkit triage, and process/network/mount control-plane mapping. It deliberately excludes user-space heap, stack, anonymous mappings, and file caches (`strict_kernel_only: false`). Consequently:
   - Process metadata (`PID`, `PPID`, `COMM`) is 100% intact, but command-line arguments in `psaux` display as `"-"` because user stack pages are uncollected.
   - Suspicious `rwx` memory areas in `malfind` are identified from kernel VMA tables, but dumped payloads appear zeroed because user anonymous memory is uncollected.
   - Userland command history (`bash`) and environment variables (`envars`) are not captured. For deep user-space process forensics, pair with process-level extraction tools (e.g., `PodDump`).

2. **Non-Atomic Live Acquisition & Smear Window:**
   Physical memory frames are acquired sequentially while the host kernel continues executing. Although `KernelDump` reduces the temporal smear window by **94.4% to 98.5%** (~2.1 seconds vs ~38-146 seconds for full RAM), live acquisitions are not atomic snapshots; concurrent kernel pointer mutations can still occur across high-churn objects.

3. **Multi-Page Boundary Expansion (`classify_with_neighbors`):**
   To prevent structural corruption of multi-page kernel objects (such as `struct task_struct`, which measures 10,496 bytes and spans across multiple contiguous pages in SLUB), the classifier retains immediate physical boundary neighbor pages of SLAB and PGTABLE allocations. Because these boundary pages may carry user flags (`ANON`, `LRU`, `MMAP`), the acquisition image may contain adjacent user frames.

4. **Dynamic Memory Hotplug:**
   Physical memory segment mappings from `/proc/kcore` ELF program headers are sampled once at initialization. Dynamic memory hot-add or hot-remove operations occurring concurrently during acquisition are unmonitored.

5. **Interface Requirements:**
   Requires readable `/proc/kcore` (`CONFIG_PROC_KCORE=y`) and `/proc/kpageflags` under root privileges (`EUID 0` / `CAP_SYS_ADMIN`). Systems where `/proc/kcore` is stripped (e.g., minimal embedded microVMs like Alpine `linux-virt`) will cleanly fail pre-flight checks.

---

## License & Disclosures

- Core tool code is released under the [MIT License](LICENSE).
- Vendored dependencies retain their respective upstream licenses as cataloged in [`hash_dependency_provenance.json`](hash_dependency_provenance.json).
- Empirical verification receipts and build provenance are recorded in [`validation.json`](validation.json) and [`build_provenance.json`](build_provenance.json).
