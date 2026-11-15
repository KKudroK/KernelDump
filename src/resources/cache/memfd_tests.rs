use super::super::provenance_tests::TestBtf;
use super::*;
use std::io::Write;

const BASE: u64 = 0xffff888000000000;
const TASK1: u64 = BASE + 0x100;
const TASK2: u64 = BASE + 0x140;
const MM1: u64 = BASE + 0x200;
const MM2: u64 = BASE + 0x240;
const VMA1: u64 = BASE + 0x300;
const VMA2: u64 = BASE + 0x380;
const FILE: u64 = BASE + 0x400;
const INODE: u64 = BASE + 0x500;
const MAPPING: u64 = BASE + 0x600;

fn seed() -> MemfdSeed {
    MemfdSeed {
        start: 0x10000,
        end: 0x11000,
        page_offset: 0,
        inode: 123,
    }
}

fn fixture(run: impl FnOnce(&mut Scan<'_, '_>, &File)) {
    let mut b = TestBtf::new();
    let u64t = b.int("u64", 8);
    let ptr = b.record(&[0, 2 << 24, 0]);
    let rb = b.structure("rb_node", 16, &[("rb_left", ptr, 0), ("rb_right", ptr, 8)]);
    let root = b.structure("rb_root", 8, &[("rb_node", ptr, 0)]);
    let cached = b.structure("rb_root_cached", 8, &[("rb_root", root, 0)]);
    let shared = b.structure("vma_shared", 16, &[("rb", rb, 0)]);
    b.structure(
        "task_struct",
        24,
        &[("pid", u64t, 0), ("start_time", u64t, 8), ("mm", ptr, 16)],
    );
    let mt = b.structure("maple_tree", 8, &[("ma_root", ptr, 0)]);
    b.structure("mm_struct", 8, &[("mm_mt", mt, 0)]);
    b.structure(
        "vm_area_struct",
        64,
        &[
            ("vm_start", u64t, 0),
            ("vm_end", u64t, 8),
            ("vm_mm", ptr, 16),
            ("vm_file", ptr, 24),
            ("vm_pgoff", u64t, 32),
            ("vm_flags", u64t, 40),
            ("shared", shared, 48),
        ],
    );
    b.structure("file", 16, &[("f_inode", ptr, 0), ("f_mapping", ptr, 8)]);
    b.structure("files_struct", 8, &[("fdt", ptr, 0)]);
    b.structure(
        "fdtable",
        24,
        &[("max_fds", u64t, 0), ("fd", ptr, 8), ("open_fds", ptr, 16)],
    );
    b.structure(
        "inode",
        40,
        &[
            ("i_mode", u64t, 0),
            ("i_nlink", u64t, 8),
            ("i_ino", u64t, 16),
            ("i_sb", ptr, 24),
            ("i_size", u64t, 32),
        ],
    );
    b.structure("super_block", 8, &[("s_magic", u64t, 0)]);
    let xa = b.structure("xarray", 8, &[("xa_head", ptr, 0)]);
    let slots = b.record(&[0, 3 << 24, 0, ptr, u64t, 64]);
    b.structure("xa_node", 520, &[("shift", u64t, 0), ("slots", slots, 8)]);
    b.structure(
        "address_space",
        24,
        &[("host", ptr, 0), ("i_mmap", cached, 8), ("i_pages", xa, 16)],
    );
    b.structure("page", 64, &[("flags", u64t, 0), ("mapping", ptr, 24)]);
    b.structure("folio", 64, &[("index", u64t, 32)]);
    let en = b.name("pageflags");
    let head = b.name("PG_head");
    let uptodate = b.name("PG_uptodate");
    b.record(&[en, (6 << 24) | 2, 4, head, 3, uptodate, 4]);
    let path =
        std::env::temp_dir().join(format!("kerneldump_memfd_{}_{}", std::process::id(), now()));
    let mut core = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut data = vec![0u8; 16 * PAGE as usize];
    let mut put = |va: u64, value: u64| {
        let at = (va - BASE) as usize;
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    for (task, pid, mm, vma) in [(TASK1, 42, MM1, VMA1), (TASK2, 43, MM2, VMA2)] {
        put(task, pid);
        put(task + 8, 123456 + pid);
        put(task + 16, mm);
        put(mm, vma);
        put(vma, 0x10000);
        put(vma + 8, 0x11000);
        put(vma + 16, mm);
        put(vma + 24, FILE);
        put(vma + 40, 8);
    }
    put(VMA1 + 56, VMA2 + 48);
    put(FILE, INODE);
    put(FILE + 8, MAPPING);
    put(INODE, 0x8000);
    put(INODE + 16, 123);
    put(INODE + 24, BASE + 0x700);
    put(INODE + 32, PAGE);
    put(BASE + 0x700, 0x01021994);
    put(MAPPING, INODE);
    put(MAPPING + 8, VMA1 + 48);
    let page = BASE + 0x8000 + 12 * 64;
    put(MAPPING + 16, page);
    put(page + 24, MAPPING);
    core.write_all(&data).unwrap();
    let segs = [Segment {
        offset: 0,
        va: BASE,
        pa: 0,
        bytes: data.len() as u64,
    }];
    let ram = [(0, data.len() as u64)];
    let mut plan = Resources::default();
    let mut scan = Scan {
        mm_owners: BTreeMap::new(),
        cache: CacheState::default(),
        code_targets: vec![],
        btf: b.finish(),
        live: Live {
            core: &core,
            segs: &segs,
            ram: &ram,
            deadline: now() + 5_000_000_000,
            read_limit: MAX_READ_BYTES,
            read_bytes: Cell::new(0),
            calls: Cell::new(0),
            root: 0,
            levels: 4,
        },
        plan: &mut plan,
        fields: RefCell::new(HashMap::new()),
        vmemmap: BASE + 0x8000,
        page_size: 64,
        files: BTreeSet::new(),
        tables: BTreeSet::new(),
        tasks: 0,
        thread_tasks: BTreeSet::new(),
        fd_refs: 0,
        sockets: 0,
        skbs: 0,
        policy_truncations: 0,
        task_identity: json!({"pid":42}),
        task_checks: vec![],
    };
    scan.index_mm_owner(TASK1, 42).unwrap();
    scan.index_mm_owner(TASK2, 43).unwrap();
    run(&mut scan, &core);
    drop(scan);
    drop(core);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn pure_btf_scan_mm_discovers_memfd_and_cow_and_excludes_linked_tmpfs() {
    let mut b = TestBtf::new();
    let u8t = b.int("u8", 1);
    let u64t = b.int("u64", 8);
    let ptr = b.record(&[0, 2 << 24, 0]);
    let rb = b.structure("rb_node", 16, &[("rb_left", ptr, 0), ("rb_right", ptr, 8)]);
    let root = b.structure("rb_root", 8, &[("rb_node", ptr, 0)]);
    let cached = b.structure("rb_root_cached", 8, &[("rb_root", root, 0)]);
    let shared = b.structure("vma_shared", 16, &[("rb", rb, 0)]);
    b.structure(
        "task_struct",
        24,
        &[("pid", u64t, 0), ("start_time", u64t, 8), ("mm", ptr, 16)],
    );
    let mt = b.structure("maple_tree", 8, &[("ma_root", ptr, 0)]);
    b.structure("mm_struct", 8, &[("mm_mt", mt, 0)]);
    let meta = b.structure("maple_metadata", 2, &[("end", u8t, 0)]);
    let pivots15 = b.record(&[0, 3 << 24, 0, ptr, u64t, 15]);
    let slots16 = b.record(&[0, 3 << 24, 0, ptr, u64t, 16]);
    let mr64 = b.structure(
        "maple_range_64",
        256,
        &[
            ("pivot", pivots15, 0),
            ("slot", slots16, 120),
            ("meta", meta, 248),
        ],
    );
    let ma64 = b.structure(
        "maple_arange_64",
        256,
        &[
            ("pivot", pivots15, 0),
            ("slot", slots16, 120),
            ("meta", meta, 248),
        ],
    );
    b.structure(
        "maple_node",
        264,
        &[
            ("parent", ptr, 0),
            ("slot", slots16, 8),
            ("mr64", mr64, 8),
            ("ma64", ma64, 8),
        ],
    );
    b.structure(
        "vm_area_struct",
        64,
        &[
            ("vm_start", u64t, 0),
            ("vm_end", u64t, 8),
            ("vm_mm", ptr, 16),
            ("vm_file", ptr, 24),
            ("vm_pgoff", u64t, 32),
            ("vm_flags", u64t, 40),
            ("shared", shared, 48),
        ],
    );
    b.structure("file", 16, &[("f_inode", ptr, 0), ("f_mapping", ptr, 8)]);
    b.structure("files_struct", 8, &[("fdt", ptr, 0)]);
    b.structure(
        "fdtable",
        24,
        &[("max_fds", u64t, 0), ("fd", ptr, 8), ("open_fds", ptr, 16)],
    );
    b.structure(
        "inode",
        40,
        &[
            ("i_mode", u64t, 0),
            ("i_nlink", u64t, 8),
            ("i_ino", u64t, 16),
            ("i_sb", ptr, 24),
            ("i_size", u64t, 32),
        ],
    );
    b.structure("super_block", 8, &[("s_magic", u64t, 0)]);
    let xa = b.structure("xarray", 8, &[("xa_head", ptr, 0)]);
    let slots = b.record(&[0, 3 << 24, 0, ptr, u64t, 64]);
    b.structure("xa_node", 520, &[("shift", u64t, 0), ("slots", slots, 8)]);
    b.structure(
        "address_space",
        24,
        &[("host", ptr, 0), ("i_mmap", cached, 8), ("i_pages", xa, 16)],
    );
    b.structure("page", 64, &[("flags", u64t, 0), ("mapping", ptr, 24)]);
    b.structure("folio", 64, &[("index", u64t, 32)]);
    let en = b.name("pageflags");
    let head = b.name("PG_head");
    let uptodate = b.name("PG_uptodate");
    b.record(&[en, (6 << 24) | 2, 4, head, 3, uptodate, 4]);

    let path = std::env::temp_dir().join(format!(
        "kerneldump_maple_scan_{}_{}",
        std::process::id(),
        now()
    ));
    let mut core = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut data = vec![0u8; 16 * PAGE as usize];
    let node = BASE + 0x1000;
    data[(node + 8 + 248 - BASE) as usize] = 2; // mr64.meta.end = 2 -> 3 populated slots
    let mut put = |va: u64, value: u64| {
        let at = (va - BASE) as usize;
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    let vma_linked = BASE + 0x3c0;
    let vma_cow = BASE + 0x440;
    let file_linked = BASE + 0x4c0;
    let inode_linked = BASE + 0x540;
    put(TASK1, 42);
    put(TASK1 + 8, 123456);
    put(TASK1 + 16, MM1);
    // Maple leaf node (kind=1 -> (1<<3)|2) holding memfd VMA, linked tmpfs VMA, and COW exec VMA.
    put(MM1, node | (1 << 3) | 2);
    put(node + 8, 0x10fff); // pivot[0]
    put(node + 16, 0x20fff); // pivot[1]
    put(node + 8 + 120, VMA1); // slot[0]
    put(node + 8 + 128, vma_linked); // slot[1]
    put(node + 8 + 136, vma_cow); // slot[2]
    // slot 0: shared unlinked memfd
    put(VMA1, 0x10000);
    put(VMA1 + 8, 0x11000);
    put(VMA1 + 16, MM1);
    put(VMA1 + 24, FILE);
    put(VMA1 + 40, 8);
    // slot 1: shared linked tmpfs (i_nlink = 1 -> excluded)
    put(vma_linked, 0x20000);
    put(vma_linked + 8, 0x21000);
    put(vma_linked + 16, MM1);
    put(vma_linked + 24, file_linked);
    put(vma_linked + 40, 8);
    put(file_linked, inode_linked);
    put(inode_linked, 0x8000);
    put(inode_linked + 8, 1); // i_nlink = 1
    put(inode_linked + 16, 456);
    put(inode_linked + 24, BASE + 0x700);
    // slot 2: private executable COW backing VMA
    put(vma_cow, 0x30000);
    put(vma_cow + 8, 0x31000);
    put(vma_cow + 16, MM1);
    put(vma_cow + 24, FILE);
    put(vma_cow + 32, 0);
    put(vma_cow + 40, 4); // VM_EXEC, !VM_SHARED
    // backing unlinked file/inode
    put(FILE, INODE);
    put(FILE + 8, MAPPING);
    put(INODE, 0x8000);
    put(INODE + 16, 123);
    put(INODE + 24, BASE + 0x700);
    put(INODE + 32, PAGE);
    put(BASE + 0x700, 0x01021994);
    core.write_all(&data).unwrap();
    let segs = [Segment {
        offset: 0,
        va: BASE,
        pa: 0,
        bytes: data.len() as u64,
    }];
    let ram = [(0, data.len() as u64)];
    let mut plan = Resources::default();
    let mut scan = Scan {
        mm_owners: BTreeMap::new(),
        cache: CacheState::default(),
        code_targets: vec![crate::code_pages::CowTarget {
            va: 0x30000,
            file_offset: 0,
            physical: 13 * PAGE,
            inode: 123,
            dev: None,
        }],
        btf: b.finish(),
        live: Live {
            core: &core,
            segs: &segs,
            ram: &ram,
            deadline: now() + 5_000_000_000,
            read_limit: MAX_READ_BYTES,
            read_bytes: Cell::new(0),
            calls: Cell::new(0),
            root: 0,
            levels: 4,
        },
        plan: &mut plan,
        fields: RefCell::new(HashMap::new()),
        vmemmap: BASE + 0x8000,
        page_size: 64,
        files: BTreeSet::new(),
        tables: BTreeSet::new(),
        tasks: 0,
        thread_tasks: BTreeSet::new(),
        fd_refs: 0,
        sockets: 0,
        skbs: 0,
        policy_truncations: 0,
        task_identity: json!({"pid":42}),
        task_checks: vec![],
    };
    scan.scan_mm(TASK1, MM1).unwrap();
    assert_eq!(scan.cache.queued_by_kind, [0, 0, 1, 1]);
    assert_eq!(scan.cache.vma_seeds.len(), 1);
    assert!(scan.cache.vma_seeds.contains(&(MM1, 0x10000)));
    assert_eq!(scan.cache.cow_seen.len(), 1);
    drop(scan);
    drop(core);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn pure_btf_collect_mm_vmas_supports_legacy_mm_rb_fallback() {
    let mut b = TestBtf::new();
    let u64t = b.int("u64", 8);
    let ptr = b.record(&[0, 2 << 24, 0]);
    let rb = b.structure("rb_node", 16, &[("rb_left", ptr, 0), ("rb_right", ptr, 8)]);
    let root = b.structure("rb_root", 8, &[("rb_node", ptr, 0)]);
    b.structure("mm_struct", 8, &[("mm_rb", root, 0)]);
    b.structure("vm_area_struct", 24, &[("vm_rb", rb, 8)]);
    let path = std::env::temp_dir().join(format!(
        "kerneldump_rb_scan_{}_{}",
        std::process::id(),
        now()
    ));
    let mut core = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut data = vec![0u8; 4096];
    let mut put = |va: u64, value: u64| {
        let at = (va - BASE) as usize;
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(MM1, VMA1 + 8);
    put(VMA1 + 16, VMA2 + 8);
    core.write_all(&data).unwrap();
    let segs = [Segment {
        offset: 0,
        va: BASE,
        pa: 0,
        bytes: data.len() as u64,
    }];
    let ram = [(0, data.len() as u64)];
    let mut plan = Resources::default();
    let scan = Scan {
        mm_owners: BTreeMap::new(),
        cache: CacheState::default(),
        code_targets: vec![],
        btf: b.finish(),
        live: Live {
            core: &core,
            segs: &segs,
            ram: &ram,
            deadline: now() + 5_000_000_000,
            read_limit: MAX_READ_BYTES,
            read_bytes: Cell::new(0),
            calls: Cell::new(0),
            root: 0,
            levels: 4,
        },
        plan: &mut plan,
        fields: RefCell::new(HashMap::new()),
        vmemmap: BASE + 0x800,
        page_size: 64,
        files: BTreeSet::new(),
        tables: BTreeSet::new(),
        tasks: 0,
        thread_tasks: BTreeSet::new(),
        fd_refs: 0,
        sockets: 0,
        skbs: 0,
        policy_truncations: 0,
        task_identity: Value::Null,
        task_checks: vec![],
    };
    let vmas = scan.collect_mm_vmas(MM1).unwrap();
    assert_eq!(vmas, vec![VMA1, VMA2]);
    let _ = u64t;
    drop(scan);
    drop(core);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn closed_fd_memfd_resolves_two_owners_and_rechecks_identity() {
    fixture(|scan, core| {
        // No files_struct or fdtable exists in this fixture.
        scan.memfd_vma(TASK1, &seed()).unwrap();
        let reverse = &scan.cache.reverse_observations[0]["vmas"];
        assert_eq!(reverse[0]["host_pids"], json!([42]));
        assert_eq!(reverse[1]["host_pids"], json!([43]));
        assert_eq!(reverse[1]["file_byte_end_exclusive"], PAGE);
        let payload = scan
            .plan
            .evidence
            .iter()
            .find(|e| e.detail["role"] == "file_bytes")
            .unwrap();
        assert_eq!(payload.detail["physical_start"], 12 * PAGE);
        let witness = || {
            scan.plan.witness(0, 16 * PAGE, true, |va, buf| {
                virtual_read(core, scan.live.segs, va, buf)
            })
        };
        assert!(
            witness()
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["same_fields"] == true)
        );
        // A reverse owner execs: the payload's physical page is unchanged.
        core.write_all_at(&(BASE + 0x900).to_le_bytes(), TASK2 + 16 - BASE)
            .unwrap();
        assert!(
            witness()
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["same_fields"] == false)
        );
        let finished = scan.plan.finish();
        assert_eq!(finished["complete"], true);
        assert!(finished["live_drift_count"].as_u64().unwrap() > 0);
    });
}

#[test]
fn stale_maps_inode_or_private_vma_never_retains_payload() {
    fixture(|scan, core| {
        let mut wrong = seed();
        wrong.inode += 1;
        assert!(
            scan.memfd_vma(TASK1, &wrong)
                .unwrap_err()
                .to_string()
                .contains("inode")
        );
        core.write_all_at(&0u64.to_le_bytes(), VMA1 + 40 - BASE)
            .unwrap();
        assert!(scan.memfd_vma(TASK1, &seed()).is_err());
        assert!(scan.plan.evidence.is_empty());
    });
}

#[test]
fn reverse_tree_rejects_cycles_missing_source_and_changed_owner() {
    fixture(|scan, core| {
        assert!(
            scan.reverse_memfd_vmas(MAPPING, BASE + 0x999, &mut vec![])
                .is_err()
        );
        core.write_all_at(&(VMA1 + 48).to_le_bytes(), VMA2 + 48 - BASE)
            .unwrap();
        assert!(
            scan.reverse_memfd_vmas(MAPPING, VMA1, &mut vec![])
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        core.write_all_at(&0u64.to_le_bytes(), VMA2 + 48 - BASE)
            .unwrap();
        core.write_all_at(&44u64.to_le_bytes(), TASK2 - BASE)
            .unwrap();
        assert!(
            scan.reverse_memfd_vmas(MAPPING, VMA1, &mut vec![])
                .unwrap_err()
                .to_string()
                .contains("identity")
        );
    });
}

#[test]
fn reverse_unknown_owner_and_private_mapping_are_explicit() {
    fixture(|scan, core| {
        scan.mm_owners.remove(&MM2);
        core.write_all_at(&0u64.to_le_bytes(), VMA2 + 40 - BASE)
            .unwrap();
        core.write_all_at(&1u64.to_le_bytes(), VMA2 + 32 - BASE)
            .unwrap();
        let records = scan.reverse_memfd_vmas(MAPPING, VMA1, &mut vec![]).unwrap();
        assert_eq!(records[1]["host_pids"], json!([]));
        assert_eq!(records[1]["shared"], false);
        assert_eq!(records[1]["file_byte_start"], PAGE);
    });
}

#[test]
fn mm_discovery_is_deferred_deduplicated_and_bounded() {
    fixture(|scan, _| {
        scan.queue_memfd_discovery(TASK1).unwrap();
        scan.queue_memfd_discovery(TASK1).unwrap();
        assert_eq!(scan.cache.maps_jobs.len(), 1);
        scan.live.read_limit = scan.live.read_bytes.get();
        let before = scan.live.calls.get();
        assert!(scan.scan_mm(TASK1, MM1).is_err());
        assert_eq!(scan.live.calls.get(), before);
        scan.live.read_limit = MAX_READ_BYTES;
        scan.live.deadline = 0;
        assert!(scan.scan_mm(TASK1, MM1).is_err());
    });
}

#[test]
fn cache_job_limit_applies_after_pending_jobs_are_drained() {
    fixture(|scan, _| {
        for _ in 0..MAX_JOBS {
            scan.queue_cache(JobKind::Vma {
                task: TASK1,
                seed: seed(),
            });
        }
        scan.cache.jobs.clear();
        scan.queue_cache(JobKind::Vma {
            task: TASK1,
            seed: seed(),
        });
        assert!(scan.cache.jobs.is_empty());
        assert_eq!(scan.cache.omitted, 1);
    });
}

#[test]
fn memfd_above_old_64kib_is_fully_retained_and_above_16mib_keeps_prefix() {
    fixture(|scan, core| {
        core.write_all_at(&(96 * 1024u64).to_le_bytes(), INODE + 32 - BASE)
            .unwrap();
        scan.memfd_vma(TASK1, &seed()).unwrap();
        assert_eq!(scan.cache.oversized, 0);
        assert_eq!(scan.cache.hits, 1);
        assert_eq!(scan.cache.misses, 23);
    });
    fixture(|scan, core| {
        core.write_all_at(&(MAX_FILE + 32 * 1024).to_le_bytes(), INODE + 32 - BASE)
            .unwrap();
        scan.memfd_vma(TASK1, &seed()).unwrap();
        assert_eq!(scan.cache.oversized, 1);
        let retained = scan
            .plan
            .evidence
            .iter()
            .find(|e| e.detail["role"] == "file_bytes");
        assert!(retained.is_some());
        assert_eq!(scan.cache.hits, 1);
    });
}

#[test]
fn linked_tmpfs_fd_is_excluded_without_affecting_unlinked_files() {
    fixture(|scan, core| {
        let origin = prepare_fd(scan, core);
        core.write_all_at(&1u64.to_le_bytes(), INODE + 8 - BASE)
            .unwrap();
        scan.queue_file_cache(FILE, origin.clone()).unwrap();
        assert_eq!(scan.cache.excluded, 1);
        assert!(scan.cache.jobs.is_empty());
        scan.small_file(FILE, origin).unwrap();
        assert_eq!(scan.cache.excluded, 2);
        assert!(scan.plan.evidence.is_empty());
    });
}

#[test]
fn full_fd_bucket_does_not_exclude_mapped_only_memfd_jobs() {
    fixture(|scan, _| {
        for _ in 0..MAX_JOBS + 1 {
            scan.queue_cache(JobKind::Fd {
                file: FILE,
                origin: json!({}),
            });
        }
        scan.queue_cache(JobKind::Vma {
            task: TASK1,
            seed: seed(),
        });
        assert_eq!(scan.cache.queued_by_kind, [MAX_JOBS, 0, 1, 0]);
        assert_eq!(scan.cache.omitted, 1);
    });
}

fn prepare_fd(scan: &mut Scan<'_, '_>, core: &File) -> Value {
    for (at, value) in [
        (0x900, BASE + 0xa00),
        (0xa00, 64),
        (0xa08, BASE + 0xb00),
        (0xa10, BASE + 0xc00),
        (0xb00, FILE),
        (0xc00, 1),
    ] {
        core.write_all_at(&value.to_le_bytes(), at).unwrap();
    }
    scan.live.deadline = now() + 5_000_000_000;
    json!({"files":BASE+0x900,"table":BASE+0xa00,"array":BASE+0xb00,"fd":0})
}

#[test]
fn cache_fd_validation_ignores_other_allocation_bits_but_detects_target_close() {
    fixture(|scan, core| {
        let origin = prepare_fd(scan, core);
        scan.small_file(FILE, origin).unwrap();
        assert_eq!(scan.cache.hits, 1);
        core.write_all_at(&3u64.to_le_bytes(), 0xc00).unwrap();
        let observed = scan.plan.witness(0, 16 * PAGE, true, |va, data| {
            virtual_read(core, scan.live.segs, va, data)
        });
        assert!(
            observed
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["same_fields"] == true)
        );
        core.write_all_at(&2u64.to_le_bytes(), 0xc00).unwrap();
        let closed = scan.plan.witness(0, 16 * PAGE, true, |va, data| {
            virtual_read(core, scan.live.segs, va, data)
        });
        assert!(
            closed
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["same_fields"] == false)
        );
    });
}

#[test]
fn bad_file_cache_index_does_not_discard_independent_later_page() {
    fixture(|scan, core| {
        let origin = prepare_fd(scan, core);
        let page = BASE + 0x8000 + 12 * 64;
        for (at, value) in [
            (INODE + 32 - BASE, 2 * PAGE),
            (MAPPING + 16 - BASE, BASE + 0x1002),
            (0x1008, 2),
            (0x1010, page),
            (page + 32 - BASE, 1),
        ] {
            core.write_all_at(&value.to_le_bytes(), at).unwrap();
        }
        scan.small_file(FILE, origin).unwrap();
        assert_eq!(scan.cache.hits, 1);
        assert!(
            scan.plan
                .evidence
                .iter()
                .any(|e| e.detail["role"] == "file_bytes" && e.detail["file_offset"] == PAGE)
        );
        let result = scan.plan.finish();
        assert_eq!(result["complete"], false);
        assert!(
            result["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["stage"] == "file_cache_index")
        );
    });
}
