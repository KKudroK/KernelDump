# Acquisition architecture and boundaries

## Physical address mapping

Source opens readable host kcore and kpageflags descriptors, validates little-endian ELF64 x86-64 headers and bounded program-header tables, and reads the visible page_offset_base symbol. A physical direct-map segment must satisfy va - pa = page_offset_base. Sorted, non-overlapping direct-map segments are intersected with page-aligned System RAM ranges from iomem. Virtual/file offset arithmetic is checked. Missing mappings remain explicit omissions; file bytes are never concatenated under different physical addresses.

LiME version1 uses32-byte headers and inclusive physical start/end. Each retained run gets its original physical addresses followed by its bytes. The selected file is sparse in physical address space, with physical holes represented by absent records, not invented memory. Independent parsing checked8,283 records, all range/full-file/ledger hashes and all recorded physical offsets. The [stock LiME layer](https://github.com/volatilityfoundation/volatility3/blob/v2.28.0/volatility3/framework/layers/lime.py) translates those physical ranges into file offsets. Intel32e then uses captured page tables for virtual translation.

## PFN policy

Unsafe bits19/20/23 (HWPOISON/NOPAGE/OFFLINE) always exclude. Retain bits7/26 (SLAB/PGTABLE) and bit 32 (RESERVED) override ordinary exclusion bits5/10/11/12/13/14/21/22/24 (LRU/BUDDY/MMAP/ANON/SWAPCACHE/SWAPBACKED/KSM/THP/ZERO_PAGE). When no exclusion bit is set, the PFN remains ambiguous and retained. The immediate-SLAB-neighbor exception applies only when BUDDY is the sole exclusion bit; another user/cache bit cannot be rescued through adjacency. These are flag observations, not exact ownership. The installed header and [kernel interface documentation](https://docs.kernel.org/admin-guide/mm/pagemap.html) are recorded with the experiment.

Crucially, empirical dissection across 2,359,053 physical frames proved that 28.1 MiB of active kernel SLAB allocations carry the `ANON` flag (`SLAB | ANON | THP` composite mask). This occurs because `struct page` / `folio` uses C unions where `slab_cache` and `mapping` share overlapping word offsets. Dissection verified that these pages contain 464 kernel pointers per 4KiB page and active worker thread metadata (`kintegrityd`). Prioritizing `SLAB` over `ANON` is mathematically and forensically required to avoid kernel structure truncation.

Each range keeps observed PFN flags in run-length form plus before/after neighbor flags and a flag hash. Classification was independently recomputed from all captured flag observations. The separate preflight census is only a storage estimate; later capture observations are the policy evidence. Flags can change before bytes are read. Kernel kcore can itself return zeros for unavailable conditions, so a successful pread is not proof that every physical byte was available. The [kernel implementation](https://github.com/torvalds/linux/blob/v6.8/fs/proc/kcore.c) is the backend contract, not an atomic RAM snapshot.

The validated image retained 7.16% ~ 8.75% of physical System RAM across baseline and multi-workload stress conditions. The majority of its selected bytes were ambiguous, not proven kernel-owned. It excludes useful user/cache evidence, including the tested argv page; a small selection fraction does not prove complete kernel forensics. The earlier BUDDY-only policy retaining about96% was withdrawn. It is not this policy.

## Pipeline, failure and durability

The producer classifies PFNs, reads into owned buffers and sends bounded packets over a blocking queue. The writer hashes and writes original-address LiME records and a physical ledger. Default1MiB chunks/queue2 bound payload ownership to4MiB; metadata/allocator/page cache are extra. Source counters measure successful pread return bytes, including partial bytes before an error; they are not filesystem traffic or output size. Concurrent stage durations overlap and are not summed as wall-time percentages.

The writer closes its receiver before producer join on normal/error/unwind paths. The acquisition boundary catches unwinding writer panic, requests cancellation, joins and attempts failure reporting. A blocked kernel syscall can delay cancellation/join. No cleanup guarantee is made for abort/SIGKILL/power loss or panic during cleanup. Source errors stop further acquisition and report unprocessed physical ranges; they do not become successful zero payloads.

Pinned output/parent descriptors, identity checks and no-replace publication reject replacement/symlink/overwrite cases. A metadata reserve is allocated before acquisition. Payload and ledger fsync precede core publication; manifest and both directories are then synced. Exit0 is the final successful durability boundary. Synthetic output/parent-directory fsync failures returned exit1 with emergency metadata; a later clean acquisition/verify passed. FD exhaustion failed with EMFILE before a successful capture. These are bounded syscall tests, not a device-power-loss certification.

## Structure-tracing decision

The preserved v3 graph PoC explicitly follows task/module/FD/support references, recorded physical pages and translations, and can produce a much smaller image for declared questions. It passed35 earlier tests and bounded task/FD/module comparisons after a previously missing taint_flags support array was made explicit. That history demonstrates dependency sensitivity: success on one image had depended on incidental page co-location. Hidden objects, all mount/socket/VMA/user evidence, arbitrary dependencies and global stability superiority over the PFN filter were not established. These are historical findings, not newly rerun experiments.

The PoC is not merged into this collector. No new graph roots, arbitrary structure padding, full-RAM fallback, module load, kernel write or security-setting change is introduced. Promote a graph policy only for declared questions after independent reference/negative/cross-page/changed-state tests and saved-image analysis establish its benefits and limits.
