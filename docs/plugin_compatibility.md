# Volatility 3 compatibility

Tested on 2026-10-17 with **stock Volatility 3 2.28.0**, Debian 12 / Linux **6.1.0-53-cloud-amd64**, x86-64 and four-level paging. Collection portability and analysis compatibility are separate: collection needs no external symbols, while Volatility needs symbols matching the captured kernel.

## What works in this test

The full-RAM reference and its filtered counterpart returned identical records for `pslist` (86), `pstree` (86 including children), `sockstat` (152), `lsof` (335), `lsmod` (49), `mountinfo` (338), `ip`, `kmsg`, `ebpf`, IDT/syscall tables and other kernel metadata queries. All five controlled TCP/UDP/UNIX sockets were present. The extracted `isofs` module was byte-identical (71,334 bytes).

These are observed outputs, not guarantees for every kernel or plugin. `pagecache.Files` preserved metadata; it did not preserve every file's content. `VMCoreInfo` retained all 108 unique key/value pairs, while three duplicate note copies became one.

## Limits caused by filtering

| Plugin | Full → filtered | Meaning |
|---|---|---|
| `psaux` | 86 → 86 rows; fixture argument lost | A task row can survive without its command line |
| `envars` | 188 → 0 | Fixture environment marker lost |
| `elfs`, `library_list` | 385 → 0; 299 → 0 | Process memory is outside the collection's kernel focus; fixture libraries were 7 → 0 |
| `vmaregexscan` | 4,103 → 0 marker matches | The controlled process buffer is omitted |
| `malware.process_spoofing` | 21 of 86 rows change | Command-line names disappear; 9 `Cmdline_Spoofed` flags change from `True` to `False`. These are changed plugin flags, not 9 proven attacks. A missing command line prevents that comparison |
| `pagecache.RecoverFs` | 1,162 recovered files change | Apparent output file sizes total 90,604,972 → 1,671,168 bytes; sparse/zero-filled holes mean these are not verified recovered-byte counts |
| `psscan` | 301 scan records → error | Reading a candidate across an omitted page aborts the stock scanner |

The `psscan` failure also occurs on the actual v0.1.1 release capture. In the same-byte control, the fault is at physical `0x29a648c`, on a page excluded by its recorded LRU flags. The first candidate's `exit_state` and PID are `-1` in the full reference, so it would be rejected rather than reported as a valid task. The scanner handles an invalid exit-state value but propagates a missing-page exception from reading that field. KernelDump's filtering creates the gap; Volatility's exception handling turns this candidate-level failure into a scan-wide abort. This first failure is not evidence that KernelDump truncated a valid task. It remains a compatibility limit of these selective images, not a guarantee of complete task preservation. The 301 full-image records are scan candidates, not 301 independently verified processes.

No arbitrary neighboring pages, zero-filled substitutes or additional collection options are added to avoid this failure. `pslist` remains usable in this test, but does not replace a scan for hidden or residual task objects. Source: [stock Volatility 2.28.0 PsScan](https://github.com/volatilityfoundation/volatility3/blob/v2.28.0/volatility3/framework/plugins/linux/psscan.py).

## Failures that also occur with full RAM

| Plugin | Observed failure | Interpretation |
|---|---|---|
| `sockscan` | `AttributeError: 'NoneType' object has no attribute 'socket'` | The stock socket scanner fails on the full reference too; filtering is not required to reproduce it |
| `capabilities` | `Unsupported kernel capabilities implementation` | This kernel's `cap[2]` symbol layout is not handled by the analyzer's capability implementation |
| `kallsyms` | `TypeError: pointer_to_string takes a Pointer` | Analyzer type-handling error reproduced on both images |

The explicit `pagecache.InodePages --inode ... --dump` fixture test produced a zero-byte file on **both** images and warned of a mismatched address space. That case cannot establish a filter-caused loss. `bash`, `malfind`, credential/module checks and several tracing plugins returned no rows on both inputs. There was no positive detection fixture for those plugins, so an empty result is not a validated clean-system finding.

## How the comparison isolates filtering

1. A fresh 1 GiB Debian VM ran a process with known argv/environment/memory markers and TCP, UDP and UNIX sockets. Its kernel GNU build ID matched the official Debian debug ELF: `4409ab2b8a5a626c1ee41412e8e6189fb23ae77c`.
2. An ISF was generated from that ELF and System.map with upstream dwarf2json. The 314 installed Volatility Python source files matched the package's recorded hashes; no analyzer patches or handcrafted symbol offsets were applied.
3. The collector's development full-RAM mode supplied a 1,073,197,056-byte reference payload. The release PFN policy was applied to its recorded flags, including adjacent SLAB/PGTABLE handling, and 119,758,848 bytes were copied into a separate LiME image. Selected source/destination payload hashes matched. This compares the **same retained bytes**, rather than two changing live captures.
4. All 59 CLI plugin names (including legacy aliases) ran on both images. A separate production v0.1.1 capture ran 31 selected names plus a `psscan` diagnostic. It occurred later, so its counts are observations rather than a same-time equivalence test.

The reference uses this collector's own full-RAM mode, not an independent acquisition engine. The experiment isolates omitted pages but does not prove atomicity or independently establish every captured byte's correctness. Per-plugin limits were 180 seconds; elapsed analysis times are not a benchmark. One interrupted full-image `library_list` invocation was replaced by its completed retry; the original record is retained in the experiment.

The first guest boot enabled five-level paging (LA57). Stock Volatility's four-level translation failed even on full RAM; a manual five-level walk of the same bytes read the correct kernel banner. The main test therefore used `-cpu max,la57=off` with the same kernel and symbols. A kernel version alone does not establish analysis compatibility.

The earlier Ubuntu 6.8 image was also retried: `sockstat` completed with 4,910 rows in 123 seconds and `sockscan` with 594 rows. A historical 90-second timeout is not evidence that sockets are unsupported. The old error cannot be attributed to the kernel version without its missing original traceback.

## Historical analyzer-only diagnostic, not a product fix

An isolated analyzer prototype added an `InvalidAddressException` guard to the stock scanner's candidate `exit_state` read. The first failing candidate had `exit_state = -1`, `pid = -1` and an empty name in the full image; the stock full-image scan would reject it. It was not a demonstrated missing live task.

With that guard, the same-byte filtered scan completed: **101 records / 101 distinct PID-TID pairs**, compared with **301 records / the same 101 pairs** in full RAM. All 86 identities from `pslist` were included. The full-image result was unchanged from the stock plugin. The separately captured release image also completed (106 records). Four and six skipped-candidate warnings, respectively, remained visible.

This demonstrates a way to avoid the crash without collecting process address spaces or increasing the dump. It does **not** restore omitted duplicate/stale candidate bytes, prove every hidden task can be recovered, or make the current stock plugin compatible. The prototype is confined to the experiment; neither the installed analyzer nor the release binary was changed. The 59-plugin table below remains the unmodified-analyzer result.

File-content recovery is a separate policy choice: retaining selected file-cache pages could improve `RecoverFs`, but increases collection size and needs its own validation. `VMCoreInfo` already retained every unique key/value pair in this test, so its lower duplicate count needs no recovery fix.

## Follow-up: checking other filtering differences

An independent read-only LiME reader and four-level page-table walker compared complete kernel objects against the same full image. All 86 listed `task_struct` objects, 21 `mm_struct` objects and executable-file objects, 21 process top-level page tables, 18,196 inodes, 18,196 address-space objects, 33 superblocks and 995 reported kernel stack return slots were byte-identical. This checks those observed objects, not every possible hidden object or kernel version.

The 42 observed argument/environment pages and all 385 reported ELF-header locations had their page-table entries preserved. Their content pages were excluded: argument/environment pages carried MMAP/ANON/SWAPBACKED flags, and ELF headers carried MMAP. All 4,102 distinct pages containing the process-buffer matches were also excluded. Restoring these plugin inputs would require collecting process memory, so no collector change is made for them. `library_list` additionally depends on ELF/linker structures in process memory; a file-path listing from kernel metadata is not an equivalent replacement.

For `process_spoofing`, only `Cmdline_Basename` (21 rows) and `Cmdline_Spoofed` (9 rows) changed. Executable paths, comm names and the other fields were preserved. An unavailable command line must remain an unavailable comparison when interpreting this plugin; the scanner's `False` value is not a clean-system finding.

For `RecoverFs`, the only changed output column was `Recovered FileSize` (1,162 rows); the reported file metadata matched. The stock exporter truncates an output file to its declared inode size once at least one page is available, so output length alone cannot establish complete file recovery. Missing file contents require the corresponding cache pages; this is a collection-scope decision, not a metadata repair. No additional collection options or neighboring pages are introduced.

Fourteen focused stock CLI reruns confirmed these distinctions. Three explicit `InodePages --inode ... --dump` tests returned the same six page records on both images, including `DumpSafe=True`, but the full image produced files of 284, 15,565 and 121 bytes while the filtered outputs were all zero bytes. These six content pages had LRU flags and were excluded by the recorded policy. Here `DumpSafe` describes page/index/mapping checks; it does not establish that the content page is in the image. This positive full-image control is separate from the earlier fixture file that failed on both inputs. The table's original no-argument `InodePages` invocation required `--inode` or `--find`; its empty output is not a valid file-content test.

The new runs also reproduced fixture ELF headers (9 → 0) and environment entries (13 → 0), and matched the earlier `process_spoofing` and `pagecache.Files` output exactly. All 314 installed analyzer source files still matched the package hashes. No additional unintended kernel-object omission was found among the checked objects; source, release binary and collection policy remain unchanged. Raw follow-up evidence is retained in experiment `kerneldump_plugin_review_20261017`; this adds no new live-VM or kernel-version coverage.

## Complete observations

Counts below are parsed JSON records, including nested children. `0` means completed with no rows, **not** a positive detection test. `—` means not run on the separate live release capture. Identical means equal JSON row multisets in the full-versus-filtered control; generated module/file content was checked separately.

| Plugin | Full | Same-byte filtered | Live release | Control result |
|---|---:|---:|---:|---|
| `linux.bash.Bash` | 0 | 0 | 0 | Empty on both |
| `linux.boottime.Boottime` | 1 | 1 | 1 | Same records |
| `linux.capabilities.Capabilities` | error | error | error | Fails on both |
| `linux.check_afinfo.Check_afinfo` | 0 | 0 | — | Empty on both |
| `linux.check_creds.Check_creds` | 0 | 0 | 0 | Empty on both |
| `linux.check_idt.Check_idt` | 21 | 21 | 21 | Same records |
| `linux.check_modules.Check_modules` | 0 | 0 | 0 | Empty on both |
| `linux.check_syscall.Check_syscall` | 430 | 430 | 430 | Same records |
| `linux.ebpf.EBPF` | 11 | 11 | 11 | Same records |
| `linux.elfs.Elfs` | 385 | 0 | 0 | Changed after filtering |
| `linux.envars.Envars` | 188 | 0 | 0 | Changed after filtering |
| `linux.graphics.fbdev.Fbdev` | 0 | 0 | — | Empty on both |
| `linux.hidden_modules.Hidden_modules` | 0 | 0 | 0 | Empty on both |
| `linux.iomem.IOMem` | 31 | 31 | — | Same records |
| `linux.ip.Addr` | 5 | 5 | 5 | Same records |
| `linux.ip.Link` | 2 | 2 | 2 | Same records |
| `linux.kallsyms.Kallsyms` | error | error | — | Fails on both |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0 | 0 | — | Empty on both |
| `linux.kmsg.Kmsg` | 653 | 653 | 653 | Same records |
| `linux.kthreads.Kthreads` | 64 | 64 | — | Same records |
| `linux.library_list.LibraryList` | 299 | 0 | 0 | Changed after filtering |
| `linux.lsmod.Lsmod` | 49 | 49 | 49 | Same records |
| `linux.lsof.Lsof` | 335 | 335 | 335 | Same records |
| `linux.malfind.Malfind` | 0 | 0 | — | Empty on both |
| `linux.malware.check_afinfo.Check_afinfo` | 0 | 0 | — | Empty on both |
| `linux.malware.check_creds.Check_creds` | 0 | 0 | — | Empty on both |
| `linux.malware.check_idt.Check_idt` | 21 | 21 | — | Same records |
| `linux.malware.check_modules.Check_modules` | 0 | 0 | — | Empty on both |
| `linux.malware.check_syscall.Check_syscall` | 430 | 430 | — | Same records |
| `linux.malware.hidden_modules.Hidden_modules` | 0 | 0 | — | Empty on both |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0 | 0 | — | Empty on both |
| `linux.malware.malfind.Malfind` | 0 | 0 | 0 | Empty on both |
| `linux.malware.modxview.Modxview` | 49 | 49 | — | Same records |
| `linux.malware.netfilter.Netfilter` | 2 | 2 | 2 | Same records |
| `linux.malware.process_spoofing.ProcessSpoofing` | 86 | 86 | — | Changed after filtering |
| `linux.malware.tty_check.Tty_Check` | 3 | 3 | — | Same records |
| `linux.module_extract.ModuleExtract` | 1 | 1 | 1 | Same records |
| `linux.modxview.Modxview` | 49 | 49 | — | Same records |
| `linux.mountinfo.MountInfo` | 338 | 338 | 338 | Same records |
| `linux.netfilter.Netfilter` | 2 | 2 | — | Same records |
| `linux.pagecache.Files` | 18196 | 18196 | 18203 | Same records |
| `linux.pagecache.InodePages` | 0 | 0 | 0 | No target argument; explicit inode tests above |
| `linux.pagecache.RecoverFs` | 17209 | 17209 | — | Changed after filtering |
| `linux.pidhashtable.PIDHashTable` | 88 | 88 | — | Same records |
| `linux.proc.Maps` | 2488 | 2488 | 2474 | Same records |
| `linux.psaux.PsAux` | 86 | 86 | 86 | Changed after filtering |
| `linux.pscallstack.PsCallStack` | 995 | 995 | — | Same records |
| `linux.pslist.PsList` | 86 | 86 | 86 | Same records |
| `linux.psscan.PsScan` | 301 | error | error | Fails after filtering |
| `linux.pstree.PsTree` | 86 | 86 | 86 | Same records |
| `linux.ptrace.Ptrace` | 0 | 0 | — | Empty on both |
| `linux.sockscan.Sockscan` | error | error | error | Fails on both |
| `linux.sockstat.Sockstat` | 152 | 152 | 152 | Same records |
| `linux.tracing.ftrace.CheckFtrace` | 0 | 0 | — | Empty on both |
| `linux.tracing.perf_events.PerfEvents` | 0 | 0 | — | Empty on both |
| `linux.tracing.tracepoints.CheckTracepoints` | 0 | 0 | — | Empty on both |
| `linux.tty_check.tty_check` | 3 | 3 | — | Same records |
| `linux.vmaregexscan.VmaRegExScan` | 4103 | 0 | 0 | Changed after filtering |
| `linux.vmcoreinfo.VMCoreInfo` | 324 | 108 | 108 | Changed after filtering |

[Structured observations, image hashes and method](plugin_compatibility.json). The raw images, stdout/stderr, generated artifacts and scripts are retained in experiment `collector_readme_validation_20261017`; memory evidence is not included in this repository.
