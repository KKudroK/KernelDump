use super::*;
use source::{Memory, PAGE, Scope};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    sync::atomic::AtomicU64,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

#[path = "tests/retention_regressions.rs"]
mod retention_regressions;

fn retention_result(complete: bool, pages: u64) -> Value {
    json!({"complete":complete,"candidate_pages":pages,"read_candidate_pages":pages,
        "unread_candidate_pages":0,"issue_count":if complete {0} else {1},
        "issues":if complete {json!([])} else {json!([{"error":"synthetic reference change"}])}})
}
#[test]
fn oversized_manifest_is_rejected_before_json_or_payload_read() {
    let t = Temp::new();
    fs::create_dir(t.out()).unwrap();
    let file = File::create(t.out().join("manifest.json")).unwrap();
    file.set_len(verify::MANIFEST_LIMIT + 1).unwrap();
    let error = verify::verify(&t.out()).unwrap_err().to_string();
    assert!(error.contains("manifest exceeds 16MiB bound"), "{error}");
}
#[test]
fn unknown_status_and_scope_cannot_be_verified_as_valid_metadata() {
    let t = Temp::new();
    capture(Fake::new(), &t, Scope::FullRam);
    let p = t.out().join("manifest.json");
    let original: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    for (key, bad) in [("status", "in_progress"), ("scope", "kernel-only")] {
        let mut changed = original.clone();
        changed[key] = json!(bad);
        fs::write(&p, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(verify::verify(&t.out()).is_err());
    }
    fs::write(&p, serde_json::to_vec(&original).unwrap()).unwrap();
    verify::verify(&t.out()).unwrap();
}
#[test]
fn source_io_counts_partial_bytes_and_retries_interruption() {
    let counter = source::ReadCounter::default();
    let mut data = [0u8; 8];
    let mut calls = 0;
    let result = counter.exact_with(&mut data, 123, |b, at| {
        calls += 1;
        match calls {
            1 => {
                assert_eq!(at, 123);
                Err(std::io::ErrorKind::Interrupted.into())
            }
            2 => {
                assert_eq!(at, 123);
                b[..3].copy_from_slice(b"abc");
                Ok(3)
            }
            _ => {
                assert_eq!(at, 126);
                assert_eq!(b.len(), 5);
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
    assert_eq!(&data[..3], b"abc");
    let measured = counter.json();
    assert_eq!(measured["calls"], 3);
    assert_eq!(measured["returned_bytes"], 3);
    assert_eq!(measured["interrupted_calls"], 1);
    assert_eq!(measured["error_calls"], 1);
}
#[test]
fn source_io_eof_preserves_consumed_bytes_without_fabricating_data() {
    let t = Temp::new();
    let path = t.0.join("source");
    fs::write(&path, b"012345").unwrap();
    let file = File::open(path).unwrap();
    let counter = source::ReadCounter::default();
    let mut data = [0xa5; 8];
    use std::os::unix::fs::FileExt;
    let error = counter
        .exact_with(&mut data, 2, |b, at| file.read_at(b, at))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert_eq!(&data[..4], b"2345");
    assert_eq!(&data[4..], &[0xa5; 4]);
    assert_eq!(counter.json()["returned_bytes"], 4);
    assert_eq!(counter.json()["zero_byte_calls"], 1);
}
#[test]
fn source_io_checked_offsets_and_short_success() {
    let counter = source::ReadCounter::default();
    assert!(
        counter
            .exact_with(&mut [0; 8], u64::MAX - 1, |_, _| panic!(
                "must reject before read"
            ))
            .is_err()
    );
    assert_eq!(counter.json()["calls"], 0);
    let mut bytes = [0; 7];
    counter
        .exact_with(&mut bytes, 10, |b, at| {
            let n = b.len().min(2);
            for (i, value) in b[..n].iter_mut().enumerate() {
                *value = (at + i as u64) as u8;
            }
            Ok(n)
        })
        .unwrap();
    assert_eq!(bytes, [10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(counter.json()["returned_bytes"], 7);
    assert_eq!(counter.json()["calls"], 4);
}
#[test]
fn kernel_build_id_notes_validate_bounds() {
    let mut notes = Vec::new();
    for n in [4u32, 3, 3] {
        notes.extend(n.to_le_bytes());
    }
    notes.extend(b"GNU\0\x12\x34\xab\0");
    assert_eq!(source::gnu_build_ids(&notes).unwrap(), vec!["1234ab"]);
    notes.pop();
    assert!(source::gnu_build_ids(&notes).is_err());
    assert!(source::gnu_build_ids(&[0; 3]).is_err());
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "kernel_dump_test_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn out(&self) -> PathBuf {
        self.0.join("capture")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Fake {
    ram: Vec<(u64, u64)>,
    flags: Vec<u64>,
    hole: bool,
    failure: bool,
    panic: bool,
    replace_reserve: Option<PathBuf>,
    replace_file: Option<PathBuf>,
    occupy_file: Option<PathBuf>,
}
impl Fake {
    fn new() -> Self {
        Self {
            ram: vec![(PAGE, PAGE * 17)],
            flags: vec![0; 16],
            hole: false,
            failure: false,
            panic: false,
            replace_reserve: None,
            replace_file: None,
            occupy_file: None,
        }
    }
}
impl Memory for Fake {
    fn info(&self) -> Value {
        json!({"source":"synthetic unit fixture"})
    }
    fn ram(&self) -> &[(u64, u64)] {
        &self.ram
    }
    fn chunk(&self, at: u64, end: u64, limit: u64) -> Result<(u64, Option<u64>)> {
        Ok((
            end.min(at + limit),
            if self.hole { None } else { Some(at - PAGE) },
        ))
    }
    fn flags(&self, at: u64, bytes: u64) -> Result<Vec<u64>> {
        Ok(
            self.flags[((at - PAGE) / PAGE) as usize..((at - PAGE + bytes) / PAGE) as usize]
                .to_vec(),
        )
    }
    fn read(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        if let Some(path) = &self.replace_file {
            let saved = path.with_extension("saved");
            if !saved.exists() {
                fs::rename(path, saved)?;
                fs::write(path, b"foreign replacement")?;
            }
        }
        if let Some(path) = &self.occupy_file {
            if !path.exists() {
                fs::write(path, b"preserve destination")?;
            }
        }
        if let Some(path) = &self.replace_reserve {
            if path.is_file() {
                fs::rename(path, path.with_extension("saved"))?;
                fs::create_dir(path)?;
            }
        }
        if self.panic {
            panic!("injected worker failure")
        };
        if self.failure {
            return Err("injected read error".into());
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((offset + i as u64).wrapping_mul(37) & 255) as u8;
        }
        Ok(())
    }
}

struct CodeFake {
    inner: Fake,
    valid: bool,
}
struct ResourceFake(Fake, bool);
impl Memory for ResourceFake {
    fn info(&self) -> Value {
        self.0.info()
    }
    fn ram(&self) -> &[(u64, u64)] {
        self.0.ram()
    }
    fn chunk(&self, a: u64, b: u64, c: u64) -> crate::Result<(u64, Option<u64>)> {
        self.0.chunk(a, b, c)
    }
    fn flags(&self, a: u64, b: u64) -> crate::Result<Vec<u64>> {
        self.0.flags(a, b)
    }
    fn read(&self, a: u64, b: &mut [u8]) -> crate::Result<()> {
        self.0.read(a, b)
    }
    fn resource_pages(&self, a: u64, b: u64) -> Vec<u64> {
        (1..=3)
            .map(|i| i * PAGE)
            .filter(|p| a <= *p && *p < b)
            .collect()
    }
    fn finish_resources(&self) -> Value {
        retention_result(self.1, 3)
    }
}
#[test]
fn resource_retention_never_selects_unsafe_or_free_pages() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags = vec![1 << 5; 16];
    f.flags[1] = (1 << 5) | (1 << 19);
    f.flags[2] = 1 << 10;
    let m = capture::acquire(
        ResourceFake(f, true),
        &t.out(),
        Scope::KernelFocused,
        4096,
        1,
    )
    .unwrap();
    assert_eq!(m["payload_bytes"], PAGE);
    assert_eq!(m["unavailable_bytes"], PAGE);
    verify::verify(&t.out()).unwrap();
}
#[test]
fn incomplete_resource_discovery_cannot_publish_complete_image() {
    let t = Temp::new();
    let m = capture::acquire(
        ResourceFake(Fake::new(), false),
        &t.out(),
        Scope::KernelFocused,
        4096,
        1,
    )
    .unwrap();
    assert_eq!(m["status"], "partial");
    assert!(!t.out().join("memory.lime").exists());
    verify::verify(&t.out()).unwrap();
}
#[test]
fn shared_resource_budget_deduplicates_and_reuses_idle_shares() {
    use crate::source::allocate_extra;
    let groups = [vec![1, 2, 3, 4, 5], vec![1, 10, 11], vec![]];
    assert_eq!(
        allocate_extra(&groups, 4).into_iter().collect::<Vec<_>>(),
        vec![1, 2, 10, 11]
    );
    assert_eq!(allocate_extra(&groups, 20).len(), 7);
    assert!(allocate_extra(&groups, 0).is_empty());
    let large = [
        (0..10000).collect(),
        (10000..20000).collect(),
        (20000..30000).collect(),
    ];
    let selected = allocate_extra(&large, 4096);
    assert_eq!(selected.len(), 4096);
    for group in &large {
        let count = group.iter().filter(|p| selected.contains(p)).count();
        assert!((1365..=1366).contains(&count));
    }
}
#[test]
fn cache_never_displaces_code_or_network_at_shared_limit() {
    use crate::source::{allocate_extra, allocate_with_cache};
    let groups = [vec![10, 20, 30], vec![40, 50, 60]];
    assert_eq!(
        allocate_with_cache(&groups, &[1, 2, 3, 4], 4),
        allocate_extra(&groups, 4)
    );
    assert_eq!(
        allocate_with_cache(&groups, &[10, 20, 1, 2, 3], 8)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![1, 2, 10, 20, 30, 40, 50, 60]
    );
    assert!(allocate_with_cache(&groups, &[1], 0).is_empty());
}
impl Memory for CodeFake {
    fn info(&self) -> Value {
        self.inner.info()
    }
    fn ram(&self) -> &[(u64, u64)] {
        self.inner.ram()
    }
    fn chunk(&self, a: u64, b: u64, c: u64) -> Result<(u64, Option<u64>)> {
        self.inner.chunk(a, b, c)
    }
    fn flags(&self, a: u64, b: u64) -> Result<Vec<u64>> {
        self.inner.flags(a, b)
    }
    fn read(&self, a: u64, b: &mut [u8]) -> Result<()> {
        self.inner.read(a, b)
    }
    fn code_pages(&self, a: u64, b: u64) -> Vec<u64> {
        [PAGE, 2 * PAGE, 3 * PAGE]
            .into_iter()
            .filter(|p| a <= *p && *p < b)
            .collect()
    }
    fn code_witness(&self, a: u64, _b: u64, after: bool) -> Value {
        json!([{"physical":a,"after":after,"same_pfn":self.valid}])
    }
    fn finish_code_pages(&self) -> Value {
        retention_result(self.valid, 3)
    }
}
#[test]
fn code_candidate_preserves_only_anon_and_never_overrides_unsafe() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags = vec![1 << 12; 16];
    f.flags[1] = (1 << 12) | (1 << 19);
    f.flags[2] = 1 << 10;
    let m = capture::acquire(
        CodeFake {
            inner: f,
            valid: true,
        },
        &t.out(),
        Scope::KernelFocused,
        4096,
        1,
    )
    .unwrap();
    assert_eq!(m["payload_bytes"], PAGE);
    assert_eq!(m["unavailable_bytes"], PAGE);
    let ledger = fs::read_to_string(t.out().join("ranges.jsonl")).unwrap();
    let rows: Vec<Value> = ledger
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(rows[0]["additional_code_bytes"], PAGE);
    assert_eq!(rows[1]["status"], "unsafe_pfn");
    assert_eq!(rows[2]["status"], "policy_excluded");
    verify::verify(&t.out()).unwrap();
}
#[test]
fn changed_code_reference_cannot_publish_complete_image() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags = vec![1 << 12; 16];
    let m = capture::acquire(
        CodeFake {
            inner: f,
            valid: false,
        },
        &t.out(),
        Scope::KernelFocused,
        4096,
        1,
    )
    .unwrap();
    assert_eq!(m["status"], "partial");
    assert!(!t.out().join("memory.lime").exists());
    assert_eq!(m["errors"][0]["stage"], "code_page_retention");
    verify::verify(&t.out()).unwrap();
}
fn capture(f: Fake, t: &Temp, scope: Scope) -> Value {
    capture::acquire(f, &t.out(), scope, 16384, 2).unwrap()
}
#[test]
fn full_round_trip_and_corruption() {
    let t = Temp::new();
    let m = capture(Fake::new(), &t, Scope::FullRam);
    assert_eq!(m["status"], "complete_for_policy");
    assert_eq!(verify::verify(&t.out()).unwrap()["payload_bytes"], 65536);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(t.out().join("memory.lime"))
        .unwrap();
    f.seek(SeekFrom::Start(60)).unwrap();
    f.write_all(b"corrupt").unwrap();
    assert!(verify::verify(&t.out()).is_err());
}
#[test]
fn filtered_addresses_preserve_gaps() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags[4..8].fill(1 << 10);
    f.flags[8..].fill(1 << 12);
    let m = capture(f, &t, Scope::KernelFocused);
    assert_eq!(m["payload_bytes"], 16384);
    assert_eq!(m["policy_excluded_bytes"], 49152);
    verify::verify(&t.out()).unwrap();
}
#[test]
fn focused_policy_excludes_user_cache_free_and_retains_kernel_metadata() {
    use crate::source::{EXCLUDE, KEEP, UNSAFE, classify};
    for bit in 0..64 {
        let flags = 1u64 << bit;
        let expected = if flags & UNSAFE != 0 {
            "unsafe_pfn"
        } else if flags & EXCLUDE != 0 {
            "policy_excluded"
        } else {
            "selected"
        };
        assert_eq!(classify(flags, Scope::KernelFocused), expected, "bit {bit}");
    }
    assert_eq!(classify(0, Scope::KernelFocused), "selected");
    assert_eq!(classify((1 << 10) | KEEP, Scope::KernelFocused), "selected");
    assert_eq!(
        classify((1 << 10) | KEEP | UNSAFE, Scope::KernelFocused),
        "unsafe_pfn"
    );
}

#[test]
fn slab_boundary_preservation_protects_multipage_objects_and_rejects_unsafe() {
    use crate::source::{EXCLUDE, UNSAFE, classify_with_neighbors};
    // Non-unsafe pages adjacent to SLAB are preserved to prevent truncating multi-page kernel objects
    for bit in 0..64 {
        let f = 1u64 << bit;
        if f & UNSAFE == 0 {
            assert_eq!(
                classify_with_neighbors(&[1 << 7, f, 1 << 7], 1, Scope::KernelFocused),
                "selected",
                "bit {bit} adjacent to SLAB must be preserved"
            );
        } else {
            assert_eq!(
                classify_with_neighbors(&[1 << 7, f, 1 << 7], 1, Scope::KernelFocused),
                "unsafe_pfn",
                "UNSAFE bit {bit} must never be reintroduced"
            );
        }
    }
    // Isolated excluded pages (not adjacent to SLAB/PGTABLE) remain strictly excluded
    for bit in 0..64 {
        let f = 1u64 << bit;
        if f & EXCLUDE != 0 && f & UNSAFE == 0 {
            assert_eq!(
                classify_with_neighbors(&[0, f, 0], 1, Scope::KernelFocused),
                "policy_excluded",
                "isolated excluded bit {bit} must remain policy_excluded"
            );
        }
    }
}
#[test]
fn unmapped_never_complete() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.hole = true;
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["status"], "partial");
    assert_eq!(m["unavailable_bytes"], 65536);
    verify::verify(&t.out()).unwrap();
}
#[test]
fn read_failure_accounts_for_unprocessed_ram() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.failure = true;
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["status"], "partial");
    assert_eq!(m["unprocessed_bytes"], 65536);
    assert_eq!(m["expected_ram_bytes"], 65536);
    assert_eq!(m["errors"][0]["physical_start"], PAGE);
    verify::verify(&t.out()).unwrap();
}
#[test]
fn worker_panic_never_becomes_complete() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.panic = true;
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["status"], "partial");
    assert!(
        m["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["stage"] == "worker")
    );
}
#[test]
fn existing_directory_never_overwritten() {
    let t = Temp::new();
    capture(Fake::new(), &t, Scope::FullRam);
    let before = fs::read(t.out().join("manifest.json")).unwrap();
    assert!(capture::acquire(Fake::new(), &t.out(), Scope::FullRam, 16384, 2).is_err());
    assert_eq!(fs::read(t.out().join("manifest.json")).unwrap(), before);
}
#[test]
fn unsafe_even_full_ram_is_partial() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags.fill(1 << 19);
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["unavailable_bytes"], 65536);
    assert_eq!(m["status"], "partial");
}
#[test]
fn ledger_and_counter_tampering_rejected() {
    let t = Temp::new();
    capture(Fake::new(), &t, Scope::FullRam);
    let p = t.out().join("manifest.json");
    let mut m: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    m["payload_bytes"] = json!(0);
    fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
    assert!(verify::verify(&t.out()).is_err());
}
#[test]
fn truncated_elf_and_hidden_iomem_rejected() {
    let t = Temp::new();
    let p = t.0.join("core");
    fs::write(&p, b"\x7fELF").unwrap();
    assert!(source::segments(&File::open(p).unwrap()).is_err());
    assert!(source::ram_ranges("00000000-00000000 : System RAM").is_err());
    assert!(source::ram_ranges("1000-4fff : System RAM\n2000-5fff : System RAM").is_err());
}
#[test]
fn sha256_known_vectors() {
    assert_eq!(
        sha(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha(&vec![b'a'; 1_000_000]),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}
#[test]
fn invalid_bounds_fail_before_creating_output() {
    let t = Temp::new();
    assert!(capture::acquire(Fake::new(), &t.out(), Scope::FullRam, 1, 2).is_err());
    assert!(!t.out().exists());
}
#[test]
fn high_kernel_va_uses_checked_difference_before_addition() {
    assert_eq!(
        source::file_offset(0x80000000, 0xffffffff80000000, 0xffffffff80000000).unwrap(),
        0x80000000
    );
    assert!(source::file_offset(u64::MAX, 1, 0).is_err());
    assert!(source::file_offset(0, 1, 2).is_err());
}
#[test]
fn reserve_cleanup_error_keeps_published_failure_manifest() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.replace_reserve = Some(t.out().join("manifest_reserve"));
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["status"], "failed");
    assert!(
        m["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["stage"] == "reserve_cleanup")
    );
    assert!(t.out().join("manifest.json").is_file());
    verify::verify(&t.out()).unwrap();
}
#[test]
fn full_capture_retains_same_time_lossy_filter_control() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags[4..8].fill(1 << 10);
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["payload_bytes"], 65536);
    let rows: Vec<Value> = fs::read_to_string(t.out().join("ranges.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        rows[1]["focused_policy_exclusions_relative"],
        json!([[0, 16384]])
    );
    assert_eq!(rows[1]["flags_rle_pages_u64"], json!([[4, 1u64 << 10]]));
    verify::verify(&t.out()).unwrap();
}

#[test]
fn slab_neighbor_preservation_crosses_chunk_boundaries() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.flags[3] = 1 << 7;
    f.flags[4..8].fill(1 << 10);
    f.flags[8] = 1 << 7;
    f.flags[15] = 1 << 10;
    let m = capture(f, &t, Scope::KernelFocused);
    assert_eq!(m["payload_bytes"], 13 * PAGE);
    assert_eq!(m["policy_excluded_bytes"], 3 * PAGE);
    verify::verify(&t.out()).unwrap();
}

#[test]
fn maximum_chunk_retains_bounded_auditable_flags() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.ram = vec![(PAGE, PAGE + 16 * 1024 * 1024)];
    f.flags = (0..4096)
        .map(|i| if i % 2 == 0 { 1u64 << 63 } else { 1u64 << 62 })
        .collect();
    capture::acquire(f, &t.out(), Scope::FullRam, 16 * 1024 * 1024, 1).unwrap();
    let ledger = fs::read(t.out().join("ranges.jsonl")).unwrap();
    assert!(ledger.len() > 65536 && ledger.len() < 131072);
    assert_eq!(
        verify::verify(&t.out()).unwrap()["payload_bytes"],
        16 * 1024 * 1024
    );
}

#[test]
fn existing_payload_destination_is_not_overwritten_or_misattributed() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.occupy_file = Some(t.out().join("memory.lime"));
    let m = capture(f, &t, Scope::FullRam);
    assert_eq!(m["status"], "failed");
    assert_eq!(m["artifact"], "memory.lime.partial");
    assert_eq!(
        fs::read(t.out().join("memory.lime")).unwrap(),
        b"preserve destination"
    );
    verify::verify(&t.out()).unwrap();
}
#[test]
fn replaced_payload_inode_cannot_be_complete_or_claim_the_foreign_path() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.replace_file = Some(t.out().join("memory.lime.partial"));
    let m = capture(f, &t, Scope::FullRam);
    assert_ne!(m["status"], "complete_for_policy");
    assert!(m["artifact"].is_null());
    assert!(
        m["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["stage"] == "output_identity")
    );
    assert_eq!(
        fs::read(t.out().join("memory.lime.partial")).unwrap(),
        b"foreign replacement"
    );
    assert!(!t.out().join("memory.lime").exists());
}
#[test]
fn replaced_ledger_inode_cannot_be_complete() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.replace_file = Some(t.out().join("ranges.jsonl"));
    let m = capture(f, &t, Scope::FullRam);
    assert_ne!(m["status"], "complete_for_policy");
    assert!(
        m["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["stage"] == "output_identity")
    );
    assert_eq!(
        fs::read(t.out().join("ranges.jsonl")).unwrap(),
        b"foreign replacement"
    );
    assert!(!t.out().join("memory.lime").exists());
}
#[test]
fn existing_manifest_destination_is_preserved_and_publication_fails() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.occupy_file = Some(t.out().join("manifest.json"));
    assert!(capture::acquire(f, &t.out(), Scope::FullRam, 16384, 2).is_err());
    assert_eq!(
        fs::read(t.out().join("manifest.json")).unwrap(),
        b"preserve destination"
    );
    assert!(t.out().join("manifest.json.partial").exists());
}

#[test]
fn storage_capacity_check_handles_normal_and_excessive_requirements() {
    let t = Temp::new();
    // 1 KiB must always succeed on valid tempfs/disk
    assert!(crate::safe_output::check_available_space(&t.out(), 1024).is_ok());
    // 100 Petabytes must fail closed
    assert!(
        crate::safe_output::check_available_space(&t.out(), 100 * 1024 * 1024 * 1024 * 1024 * 1024)
            .is_err()
    );
}

#[test]
fn fadvise_cache_eviction_succeeds_on_valid_output_file() {
    let t = Temp::new();
    let p = t.0.join("test_cache");
    let f = File::create(&p).unwrap();
    assert!(crate::safe_output::advise_dontneed(&f, 0, 0).is_ok());
    assert!(crate::safe_output::advise_sequential(&f, 0, 0).is_ok());
}

#[test]
fn readiness_check_returns_valid_structured_json() {
    let t = Temp::new();
    let rep = source::check_readiness(Some(&t.out())).unwrap();
    assert!(rep["checks"].is_array());
    assert!(rep["kernel_release"].is_string());
    assert!(rep["ready"].is_boolean());
}
