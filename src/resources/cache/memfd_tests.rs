use super::super::provenance_tests::TestBtf;
use super::*;
use std::io::{Cursor, Write};

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
    b.structure(
        "address_space",
        24,
        &[("host", ptr, 0), ("i_mmap", cached, 8), ("i_pages", xa, 16)],
    );
    b.structure("page", 64, &[("flags", u64t, 0), ("mapping", ptr, 24)]);
    b.structure("folio", 64, &[("index", u64t, 32)]);
    let en = b.name("pageflags");
    let head = b.name("PG_head");
    b.record(&[en, (6 << 24) | 1, 4, head, 3]);
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
        pod: None,
        target_seen: BTreeSet::new(),
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
fn maps_seed_requires_shared_exact_path_and_valid_fields() {
    assert_eq!(
        memfd_seed("10000-11000 rw-s 00000000 00:01 123 /memfd:test data (deleted)").unwrap(),
        Some(seed())
    );
    for line in [
        "10000-11000 rw-p 0 00:01 123 /memfd:test (deleted)",
        "10000-11000 rw-s 0 00:01 123 /tmp/memfd:ordinary",
        "10000-11000 rw-s 0 00:01 123 /tmp/name /memfd:spoof",
    ] {
        assert_eq!(memfd_seed(line).unwrap(), None);
    }
    for line in [
        "11000-10000 rw-s 0 00:01 123 /memfd:x",
        "10000-11000 rw-s 1 00:01 123 /memfd:x",
        "10000-11000 rw-s 0 00:01 0 /memfd:x",
    ] {
        assert!(memfd_seed(line).is_err());
    }
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
        assert_eq!(scan.plan.finish()["complete"], false);
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
fn proc_reads_are_deferred_deduplicated_and_bounded() {
    fixture(|scan, _| {
        scan.queue_memfd_discovery(TASK1, 42).unwrap();
        scan.queue_memfd_discovery(TASK1, 42).unwrap();
        assert_eq!(scan.cache.maps_jobs.len(), 1);
        assert_eq!(scan.cache.proc_maps_calls, 0);
        assert!(
            scan.read_memfd_maps(Cursor::new(vec![b'x'; MAX_PROC_MAPS_BYTES as usize + 1]))
                .is_err()
        );
        assert_eq!(scan.cache.proc_maps_bytes, MAX_PROC_MAPS_BYTES + 1);
        scan.live.read_limit = scan.live.read_bytes.get();
        let before = scan.cache.proc_maps_calls;
        assert!(scan.read_memfd_maps(Cursor::new(b"x")).is_err());
        assert_eq!(scan.cache.proc_maps_calls, before);
        scan.live.read_limit = MAX_READ_BYTES;
        scan.live.deadline = 0;
        assert!(scan.read_memfd_maps(Cursor::new(b"x")).is_err());
        assert_eq!(scan.cache.proc_maps_calls, before);
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
