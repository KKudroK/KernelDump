# Analyzing the saved kernel-focused image

## Required layers and symbols

Preserve memory.lime, ranges.jsonl, manifest.json, stderr and the acquisition exit status. Run kernel_dump verify first. Successful verification checks file integrity/coverage accounting; it does not prove completeness, historical durability, authenticity or application consistency.

The observed stock stack is FileLayer → LimeLayer → Intel32e → Linux kernel module/symbol table. LiME supplies physical addresses. Intel32e needs retained translation tables and a valid DTB/KASLR offset, while the Linux table needs the exact kernel build's ISF. Version text alone is insufficient: match the captured banner, GNU build IDs and BTF/layout evidence. BTF itself is not a Volatility ISF. Use symbols generated for the exact kernel, for example through the official [dwarf2json workflow](https://github.com/volatilityfoundation/dwarf2json); do not substitute another build with the same release label. Automatic identification and offset derivation are described in the [Linux stacker](https://github.com/volatilityfoundation/volatility3/blob/v2.28.0/volatility3/framework/automagic/linux.py).

The validated kernel has GNU build ID13c66e43eb7246daba94e1989d80d84129a6ba2a and BTF SHA d3805cbdc4a8882d216f45a7615961634651256d3dc07b4ff69ba4e528247b8e. Original ISF SHA is 9d341e20fa29ceeb0b821133031306b21cea4ac2414d76d67f1a1b0853d2b029. Original symbols, captured BTF/notes and field-layout proof are preserved with the detailed experiment, outside this source repository.

## Reproducing this ISF from preserved inputs

The old layout proof's missing-generation-input note is superseded by the preserved reproduction record. The accepted original ISF is generated from raw BTF, System.map and the full captured kernel banner, not a DWARF vmlinux ELF. BTF SHA d3805cbdc4a8882d216f45a7615961634651256d3dc07b4ff69ba4e528247b8e and System.map SHA1f2c7547363ed50f70a7e7c154eac7da8f52b0ec90a94851bae58be6dec3f662 match the earlier records.

The preserved lemon-btf2json v0.1.0 executable has SHA5510e8d3cbb7a698f81ca529f570018d037c2c01b00fe8bcde4efbf877a969cd. Its clean source checkout is commit211005007e8d1fbf2e23a03261d7122823608531 from [the source repository](https://github.com/eurecom-s3/lemon-btf2json). The exact executable matches the historical generation receipt;this check preserves the commit archive but does not rebuild/attest the generator binary from source.

Use an argument list to retain the full captured banner and its final newline. This fork requires --vabits48,including version queries. The validated48-bit setting is specific to this environment.

```python
import json,subprocess
manifest=json.load(open('captured_manifest.json',encoding='utf-8'))
args=['btf2json','--btf','vmlinux.btf',
      '--map','System.map-6.8.0-146-generic',
      '--banner',manifest['source']['kernel_banner'],'--vabits','48']
with open('raw.json','wb') as output:
    subprocess.run(args,stdout=output,check=True)
```

Regeneration matched all19base types,13,969user types,2,563enums and191,961symbols,including the exact banner. A mechanical stock-schema compatibility filter removes only metadata source entries of kinds btf and symdb;the complete raw provenance remains in a sidecar. After this metadata-only normalization the entire parsed JSON equals the accepted original ISF. Historical raw generation differs at linux_banner;using the full banner from captured metadata resolves that difference. No type/layout/symbol address or dump byte was adjusted.

A self-contained reproduction package with hash-checked inputs, preserved executable, clean commit archive, executable Python recipe and successful packaged-run result is in local kernel_review_20261015_01/isf_reproduction_01. No new RAM acquisition was performed. Raw BTF has no standalone GNU build-ID note:matching captured BTF plus kernel notes/build IDs establishes the recorded consistency chain,not a recovered DWARF ELF or upstream kernel-build attestation. The runtime task_struct.size overlay is still separate;273field offsets and arch_task_struct_size do not guarantee nested optional FPU tail bytes.

## Runtime task allocation overlay

On this kernel, the exact matching ISF has static task_struct size13,760 while the observed boot-time arch_task_struct_size is10,496. With the original ISF, stock PsList emitted344 rows/exit0 but found only336/345 stable PID/PPID pairs. The checked overlay emitted353 rows and found345/345;8rows fall outside the stable intersection and are not automatically labelled false positives. The same immutable image and unmodified analyzer were used.

[prepare_runtime_isf.py](../scripts/prepare_runtime_isf.py) creates a separate ISF after checking original ISF SHA, captured BTF/build ID/banner, all273 task field offsets and the captured runtime allocation. Only user_types.task_struct.size changes. The original ISF, nested optional FPU layouts, analyzer and memory bytes stay unchanged. Do not shrink arbitrary symbols or interpret beyond the runtime allocation. This is an object-readability adjustment, not repair of missing physical data or a wrong kernel build.

```sh
python3 scripts/prepare_runtime_isf.py \
  --isf EXACT_ORIGINAL_ISF.json --manifest CASE/manifest.json \
  --proof VERIFIED_LAYOUT_PROOF.json --output SYMBOL_DIR/linux/runtime.json
```

The output and its provenance path must be new; the Linux symbol directory parent must already exist. The supplied proof must be independently validated for that exact kernel. This repository does not generate an arbitrary new kernel's layout proof. For this tested build the overlay SHA is 601960013c3aedc5e522b4c9ffa58a5c0bc46227a2b1214aac2c6ddefeadf42d. An original ISF can match the kernel build and still over-read a dynamic trailing allocation; successful plugin exit alone is insufficient.

## Stock CLI example

Use unmodified Volatility3 2.28.0, an existing authorized owner for mode0700 evidence, a new cache, and the checked symbol directory:

```sh
mkdir CACHE
vol -q --offline --cache-path CACHE -s SYMBOL_DIR -r json \
  -f CASE/memory.lime --save-config checked_config.json linux.pslist.PsList
vol -q --offline --cache-path CACHE -s SYMBOL_DIR -r json \
  -c checked_config.json linux.lsmod.Lsmod
vol -q --offline --cache-path CACHE -s SYMBOL_DIR -r json \
  -c checked_config.json linux.lsof.Lsof --pid HOST_PID
```

When moving a case, regenerate its configuration with the new image/symbol paths. Saved configs contain absolute file URIs. Analysis is optional and separate from the standalone collector; do not feed later live bytes into a saved image or silently pad missing ranges. Source Python files in the existing stock analyzer were hashed before/after analysis and unchanged.

## Actual comparison with independent observations

Ground truth was read before and after the2.048s live acquisition. Stable intersections are lower-bound observations, not an atomic truth for transient/hidden objects. There was one owned sleeping fixture plus one Redis and one Nginx process in existing Pods. The fixture held24long-name files, a mapped file, pipe, loopback TCP/UDP and socketpair descriptors. Facts were not passed into the collector or stock plugins as reconstruction hints; scoped PIDs only restrict analysis.

|Question|Actual saved-image result|Boundary|
|---|---|---|
|Process inventory/tree|345/345 stable PID+PPID pairs|324/345 exact15-byte display names;21 kernel workqueue name differences retained|
|Module inventory|103/103 stable names|Not independent verification of every taint, argument or module code byte|
|Mount identity/topology|206/206 stable PID+mount IDs; parent/device/mountpoint/fstype/source fields match|Exact rows190/206;16nsfs ROOT strings are net:[inode] in proc and / in stock;3extra rootfs records remain|
|Scoped FD+inode|58/58|Three PIDs;not node-global FD coverage|
|Fixture file paths|28/28,missing/extra0|Actual captured long paths;other scoped descriptors remain separate|
|Scoped inet endpoints|6/6 FD/netns/family/address/port tuples|No global socket or application payload guarantee|
|argv negative control|PsAux exit0 with ARGS=null;known marker not recovered|Its stable user PFN was excluded by policy;argv is not a supported inference from this subset|

The [kernel proc name formatter](https://github.com/torvalds/linux/blob/v6.8/fs/proc/array.c) can decorate workqueue names, while the stock plugin reads task_struct.comm. All21 differences remain visible; PID agreement is not exact name agreement. The initial path-subset comparison reported30 extra ordinary descriptors because its expected set covered only fixture files. The correctly scoped fixture subset has28/28,extra0; the raw initial result and erratum remain preserved.

All65stable sampled anonymous/file-cache/argv PFNs were excluded. Independent LiME parsing confirmed8,283 selected records, original physical addresses, all range/full-image/ledger hashes and classifications from captured PFN flags. Incomplete user-space strings, process-memory extraction, arbitrary scanners, all kernel objects, hidden/short-lived objects and all namespace/socket evidence are not qualified by these results. No new full-RAM/same-byte omission control was collected; earlier limited full/focused comparisons remain historical.

## Comprehensive Volatility 3 Plugin Evaluation (31 Plugins Evaluated)

Evaluated across the 806.8 MiB focused image (`focused_capture/memory.lime`, 846,016,512 bytes, captured in 2.99s) and verified against the 9.00 GiB full physical RAM dump:

| Category | Plugin | Status | Rows Extracted | Forensic Parity & Coverage Note |
| :--- | :--- | :---: | :---: | :--- |
| **Process** | `linux.pslist.PsList` | SUCCESS | 272 | 100% of all running host & container processes |
| **Process Scan** | `linux.psscan.PsScan` | SUCCESS | 618 | Physical pool scan detects active and exited threads |
| **Process Tree** | `linux.pstree.PsTree` | SUCCESS | 272 | Process parent-child hierarchy completely intact |
| **PID Hash** | `linux.pidhashtable.PIDHashTable` | SUCCESS | 583 | Kernel PID lookup table matches 100% |
| **Credentials** | `linux.capabilities.Capabilities` | SUCCESS | 272 | Complete POSIX capabilities per process |
| **Cred Rootkit** | `linux.check_creds.Check_creds` | HEADER_ONLY | 0 | Clean verification (0 compromised credential structs) |
| **Kernel Workers**| `linux.kthreads.Kthreads` | SUCCESS | 193 | 100% kernel worker threads enumerated |
| **Modules** | `linux.lsmod.Lsmod` | SUCCESS | 105 | Matches `/proc/modules` 100% |
| **Module Check** | `linux.check_modules.Check_modules` | SUCCESS | 1 | Sysfs module list verification clean |
| **Syscalls** | `linux.check_syscall.Check_syscall` | SUCCESS | 441 | Complete system call dispatch table validated |
| **Interrupts** | `linux.check_idt.Check_idt` | SUCCESS | 21 | IDT handler table validated |
| **Protocol Hooks**| `linux.check_afinfo.Check_afinfo` | HEADER_ONLY | 0 | Clean verification (0 hooked network handlers) |
| **TTY Drivers** | `linux.tty_check.tty_check` | SUCCESS | 3 | TTY driver operation structures validated |
| **Notifiers** | `linux.keyboard_notifiers` | HEADER_ONLY | 0 | Clean verification (0 rogue keyboard notifiers) |
| **Network IP** | `linux.ip.Addr` & `linux.ip.Link` | SUCCESS | 26 / 15 | All Calico veth, eth0, cni interfaces recovered |
| **Mountpoints** | `linux.mountinfo.MountInfo` | SUCCESS | 1,454 | 100% container namespace mount points recovered |
| **File Descriptors**| `linux.lsof.Lsof` | SUCCESS | 10,972 | All open sockets, files, pipes across node recovered |
| **I/O Memory** | `linux.iomem.IOMem` | SUCCESS | 125 | Hardware memory layout validated |
| **Kernel Log** | `linux.kmsg.Kmsg` | SUCCESS | 3,024 | Complete dmesg ring buffer recovered |
| **Virtual Maps**| `linux.proc.Maps` | SUCCESS | 5,983 | All VMA memory ranges mapped |
| **Cmdline Args**| `linux.psaux.PsAux` | SUCCESS | 272 | Process task descriptors enumerated; ARGS omitted by design (user stack excluded) |
| **Injection** | `linux.malfind.Malfind` | SUCCESS | 5 | Injected/executable VMA ranges detected; code payload omitted by design (user anonymous pages excluded) |
| **Page Cache** | `linux.pagecache.Files` | ERROR | 7,148 | Omitted by design (user-space page cache excluded) |
| **Page Cache** | `linux.pagecache.RecoverFs` | TIMEOUT | 0 | Omitted by design (user-space page cache excluded) |
| **ELF Dumper** | `linux.elfs.Elfs` | HEADER_ONLY | 0 | Omitted by design (user-space binaries excluded) |

## Multi-Workload Stress Validation

Tested under three synthetic stress conditions on the active Kubernetes cluster:
1. **Scenario A (Memory Pressure & Page Reclaim)**: Under 3.5 GiB anonymous memory pressure (`kswapd` active, anonymous memory surging to 51.96% of RAM), capture completed in **3.42s** (718.3 MiB payload), safely omitting 4.7 GB of dirty user memory without stalling.
2. **Scenario B (Heavy Disk I/O & Dirty Cache Churn)**: Under 3.0 GiB disk write churn (page cache surging to 90.04% of RAM and dirty pages surging to 240.8 MB), capture completed in **1.51s** (774.9 MiB payload), cleanly isolating kernel structures from 8.85 GiB of dirty cache.
3. **Scenario C (Process Explosion & SLUB Fragmentation)**: Under 300 concurrent fork/exec processes (page tables surging from 14.3 MB to 35.9 MB and SLAB surging to 327.2 MB), capture completed in **2.02s** (804.9 MiB payload), successfully tracking all 300 new processes in `pslist`.

Detailed raw results and failure records are in local experiment kernel_review_20261015_01; dumps under its dump_staging root. Current source passed36public+36development unit tests, public input rejection cases, EMFILE failure handling and synthetic output/parent fsync faults. This defines tested support;plugin count alone is not an acceptance criterion.
