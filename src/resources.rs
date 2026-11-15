//! Bounded, read-only traversal of live FD/socket references using kernel BTF.
use crate::{
    Result,
    btf::{Btf, Field},
    now,
    source::{PAGE, Segment},
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    os::unix::fs::FileExt,
};

mod cache;
#[cfg(test)]
#[path = "resources/provenance_tests.rs"]
mod provenance_tests;

const PFN_MASK: u64 = 0x000f_ffff_ffff_f000;
const MAX_READ_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REFS: usize = 65_536;
const MAX_CANDIDATES: usize = 131_072;
const MAX_THREAD_TASKS: usize = 32768;
const QUEUE_BYTES: u64 = 64 * 1024;

fn metadata_owner(mut detail: Value, identity: &Value) -> Value {
    detail["pid"] = identity["pid"].clone();
    detail["process"] = identity.clone();
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bare_skb_metadata_keeps_the_target_identity() {
        let id = json!({"pid":42,"start_boottime_ns":1234,"pod_uid":"selected"});
        for role in [
            "skb_metadata",
            "shared_info_metadata",
            "fragment_page_metadata",
        ] {
            let record = metadata_owner(json!({"role":role,"skb":0x1234}), &id);
            assert_eq!(record["process"], id);
            assert_eq!(record["pid"], 42);
            assert_eq!(record["role"], role);
            assert_eq!(record["skb"], 0x1234);
        }
    }
    fn candidate() -> Resources {
        let mut r = Resources::default();
        r.pages.insert(PAGE, vec![0]);
        r.evidence.push(Evidence {
            category: "network",
            detail: json!({"bytes":5}),
            checks: vec![Check {
                address: 0xffff800000001000,
                bytes: vec![1, 2, 3, 4],
                mask: None,
            }],
        });
        r
    }
    #[test]
    fn reference_changes_and_omissions_remain_partial() {
        let r = candidate();
        assert_eq!(r.finish()["complete"], false);
        let result = r.witness(PAGE, 2 * PAGE, true, |_, data| {
            data.copy_from_slice(&[1, 2, 3, 9]);
            Ok(())
        });
        assert_eq!(result[0]["same_fields"], false);
        let drift_finish = r.finish();
        assert_eq!(drift_finish["complete"], true);
        assert_eq!(drift_finish["issue_count"], 0);
        assert_eq!(drift_finish["live_drift_count"], 1);
        assert_eq!(drift_finish["unread_candidate_pages"], 0);
        assert!(
            drift_finish["live_drift"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["error"]
                    .as_str()
                    .unwrap_or("")
                    .contains("0xffff800000001000"))
        );

        let unreadable = candidate();
        unreadable.witness(PAGE, 2 * PAGE, true, |_, _| {
            Err("synthetic read error".into())
        });
        let unreadable_finish = unreadable.finish();
        assert_eq!(unreadable_finish["complete"], false);
        assert_eq!(unreadable_finish["issue_count"], 1);

        let stable = candidate();
        stable.witness(PAGE, 2 * PAGE, true, |_, data| {
            data.copy_from_slice(&[1, 2, 3, 4]);
            Ok(())
        });
        let stable_finish = stable.finish();
        assert_eq!(stable_finish["complete"], true);
        assert_eq!(stable_finish["live_drift_count"], 0);
    }

    #[test]
    fn folio_flag_mask_ignores_volatile_state_but_rejects_geometry_or_uptodate_change() {
        let original = (1u64 << 3) | (1u64 << 4);
        let check = Check {
            address: 0,
            bytes: original.to_le_bytes().to_vec(),
            mask: Some(original),
        };
        assert!(check.matches(&(original | (1u64 << 15)).to_le_bytes()));
        assert!(!check.matches(&(1u64 << 3).to_le_bytes()));
        assert!(!check.matches(&(1u64 << 4).to_le_bytes()));
    }
    #[test]
    fn missing_btf_is_explicit_and_never_complete() {
        let file = File::open("/dev/null").unwrap();
        let result = Resources::discover(
            &file,
            &[],
            &[],
            &json!({}),
            Err("missing BTF".into()),
            now() + 1_000_000,
            &[],
        );
        assert_eq!(result.finish()["complete"], false);
        assert_eq!(result.summary()["issues_at_discovery"], 1);
    }

    #[test]
    fn discovery_live_drift_classification_preserves_complete_while_keeping_limits_partial() {
        let drift_only = Resources::default();
        for (stage, msg) in [
            ("file_cache", "cache FD closed"),
            ("mm_vma_seed", "retired Maple node"),
            ("fdtable", "reference changed during discovery"),
        ] {
            drift_only.issue_or_drift(stage, msg);
        }
        let drift_finish = drift_only.finish();
        assert_eq!(drift_finish["complete"], true);
        assert_eq!(drift_finish["issue_count"], 0);
        assert_eq!(drift_finish["live_drift_count"], 3);

        let mixed = Resources::default();
        mixed.issue_or_drift("discovery", "resource discovery budget exhausted");
        mixed.issue_or_drift("threads", "thread group identity changed");
        let mixed_finish = mixed.finish();
        assert_eq!(mixed_finish["complete"], false);
        assert_eq!(mixed_finish["issue_count"], 2);
        assert_eq!(mixed_finish["live_drift_count"], 0);
    }
}

pub fn virtual_read(core: &File, segs: &[Segment], va: u64, data: &mut [u8]) -> Result<()> {
    let end = va
        .checked_add(data.len() as u64)
        .ok_or("kernel address overflow")?;
    let mut found = segs.iter().filter(|s| s.va <= va && end <= s.va + s.bytes);
    let s = found.next().ok_or("kernel virtual address outside kcore")?;
    if found.next().is_some() {
        return Err("ambiguous kcore virtual segment".into());
    }
    core.read_exact_at(data, s.offset + (va - s.va))?;
    Ok(())
}
struct Live<'a> {
    core: &'a File,
    segs: &'a [Segment],
    ram: &'a [(u64, u64)],
    deadline: u64,
    read_limit: u64,
    read_bytes: Cell<u64>,
    calls: Cell<u64>,
    root: u64,
    levels: u8,
}
impl Live<'_> {
    fn read(&self, va: u64, n: usize) -> Result<Vec<u8>> {
        if now() >= self.deadline
            || self.read_bytes.get() + n as u64 > self.read_limit
            || n > 1024 * 1024
        {
            return Err("resource discovery budget exhausted".into());
        }
        self.read_bytes.set(self.read_bytes.get() + n as u64);
        self.calls.set(self.calls.get() + 1);
        let mut b = vec![0; n];
        virtual_read(self.core, self.segs, va, &mut b)?;
        Ok(b)
    }
    fn uint(&self, va: u64, n: usize) -> Result<u64> {
        if n == 0 || n > 8 {
            return Err("invalid scalar size".into());
        }
        let b = self.read(va, n)?;
        let mut v = [0; 8];
        v[..n].copy_from_slice(&b);
        Ok(u64::from_le_bytes(v))
    }
    fn physical_read(&self, pa: u64, n: usize) -> Result<Vec<u8>> {
        let s = self
            .segs
            .iter()
            .find(|s| {
                s.pa != u64::MAX
                    && s.pa <= pa
                    && pa
                        .checked_add(n as u64)
                        .is_some_and(|e| e <= s.pa.saturating_add(s.bytes))
            })
            .ok_or("unmapped physical metadata")?;
        self.read(s.va + (pa - s.pa), n)
    }
    fn physical(&self, va: u64) -> Result<u64> {
        if let Some(s) = self
            .segs
            .iter()
            .find(|s| s.pa != u64::MAX && s.va <= va && va < s.va + s.bytes)
        {
            let pa = s.pa.checked_add(va - s.va).ok_or("physical overflow")?;
            if self.ram.iter().any(|&(a, b)| a <= pa && pa < b) {
                return Ok(pa);
            }
        }
        if va < 0xff00_0000_0000_0000 || self.root == 0 {
            return Err("unsupported kernel address translation".into());
        }
        let mut table = self.root;
        for level in (1..=self.levels).rev() {
            let shift = 12 + (level - 1) * 9;
            let off = ((va >> shift) & 511) * 8;
            let e = u64::from_le_bytes(self.physical_read(table + off, 8)?.as_slice().try_into()?);
            if e & 1 == 0 {
                return Err("nonpresent kernel translation".into());
            }
            if level == 1 || (matches!(level, 2 | 3) && e & 128 != 0) {
                let mask = (1u64 << shift) - 1;
                let pa = (e & PFN_MASK & !mask) + (va & mask);
                if !self.ram.iter().any(|&(a, b)| a <= pa && pa < b) {
                    return Err("translated address outside RAM".into());
                }
                return Ok(pa);
            }
            if e & 128 != 0 {
                return Err("invalid upper-level huge entry".into());
            }
            table = e & PFN_MASK;
        }
        Err("no kernel translation leaf".into())
    }
}
#[derive(Clone, Debug)]
struct Check {
    address: u64,
    bytes: Vec<u8>,
    // Validate only identity-relevant bits in shared words (open_fds and folio flags).
    mask: Option<u64>,
}
impl Check {
    fn matches(&self, current: &[u8]) -> bool {
        if current.len() != self.bytes.len() {
            return false;
        }
        match self.mask {
            None => current == self.bytes,
            Some(mask) => match (
                <[u8; 8]>::try_from(current),
                <[u8; 8]>::try_from(self.bytes.as_slice()),
            ) {
                (Ok(a), Ok(b)) => u64::from_le_bytes(a) & mask == u64::from_le_bytes(b) & mask,
                _ => false,
            },
        }
    }
}
#[derive(Clone)]
struct Evidence {
    category: &'static str,
    detail: Value,
    checks: Vec<Check>,
}
#[derive(Default)]
pub struct Resources {
    pages: BTreeMap<u64, Vec<usize>>,
    evidence: Vec<Evidence>,
    summary: Value,
    issues: RefCell<Vec<Value>>,
    issue_count: Cell<u64>,
    drift: RefCell<Vec<Value>>,
    drift_count: Cell<u64>,
    visited: RefCell<BTreeSet<u64>>,
    released: RefCell<BTreeSet<u64>>,
    validation_bytes: Cell<u64>,
    validation_ns: Cell<u64>,
}
impl Resources {
    pub(crate) fn is_live_discovery_drift(msg: &str) -> bool {
        matches!(
            msg,
            "reference changed during discovery"
                | "thread group signal unavailable"
                | "socket FD bounds changed"
                | "socket FD changed"
                | "socket FD closed"
                | "cache file type changed"
                | "cache FD bounds changed"
                | "cache FD changed"
                | "cache FD closed"
                | "cache mapping inode mismatch"
                | "retired Maple node"
                | "memfd task lost mm"
                | "memfd VMA mm mismatch"
                | "memfd shared VMA changed"
                | "memfd VMA lost backing file"
                | "memfd backing inode changed or still linked"
                | "memfd address_space inode mismatch"
                | "memfd i_mmap is empty"
                | "memfd reverse VMA mapping mismatch"
                | "memfd reverse VMA invalid"
                | "memfd reverse process identity changed"
                | "source VMA absent from address_space.i_mmap"
                | "COW task lost mm"
                | "COW VMA mm mismatch"
                | "COW VMA changed or offset mismatch"
                | "COW VMA lost file"
                | "COW cache inode mismatch"
                | "COW file offset outside size"
                | "COW VMA absent or RB cycle"
                | "COW VMA absent or Maple cycle"
                | "COW VMA outside Maple slots"
        )
    }
    fn issue(&self, stage: &str, e: impl ToString) {
        self.issue_count.set(self.issue_count.get() + 1);
        let mut v = self.issues.borrow_mut();
        if v.len() < 32 {
            v.push(json!({"stage":stage,"error":e.to_string()}));
        }
    }
    fn issue_or_drift(&self, stage: &str, e: impl ToString) {
        let msg = e.to_string();
        if Self::is_live_discovery_drift(&msg) {
            self.record_drift(stage, msg);
        } else {
            self.issue(stage, msg);
        }
    }
    fn record_drift(&self, stage: &str, e: impl ToString) {
        self.drift_count.set(self.drift_count.get() + 1);
        let mut v = self.drift.borrow_mut();
        if v.len() < 32 {
            v.push(json!({"stage":stage,"error":e.to_string()}));
        }
    }
    pub fn note_skipped(&self, pa: u64, flags: u64) {
        if self.pages.contains_key(&pa)
            && !self.visited.borrow().contains(&pa)
            && self.released.borrow_mut().insert(pa)
        {
            self.record_drift(
                "released_before_read",
                format!("physical {pa:#x} flags {flags:#x}"),
            );
        }
    }
    pub fn summary(&self) -> Value {
        self.summary.clone()
    }
    pub fn addresses(&self, a: u64, b: u64) -> Vec<u64> {
        self.pages.range(a..b).map(|(&p, _)| p).collect()
    }
    pub fn category_pages(&self, category: &str) -> Vec<u64> {
        self.pages
            .iter()
            .filter(|(_, r)| r.iter().any(|&i| self.evidence[i].category == category))
            .map(|(&p, _)| p)
            .collect()
    }
    pub fn witness<F>(&self, a: u64, b: u64, after: bool, mut read: F) -> Value
    where
        F: FnMut(u64, &mut [u8]) -> Result<()>,
    {
        let started = now();
        let mut result = Vec::new();
        let mut checked = HashMap::new();
        for (&pa, indices) in self.pages.range(a..b) {
            if after {
                self.visited.borrow_mut().insert(pa);
            }
            for &index in indices {
                let e = &self.evidence[index];
                let valid = *checked.entry(index).or_insert_with(|| {
                    if self.validation_ns.get() + now() - started > 5_000_000_000
                        || self.validation_bytes.get() > 64 * 1024 * 1024
                    {
                        self.issue("validation_limit", "resource reference validation budget");
                        return false;
                    }
                    let mut valid = true;
                    let mut read_error = None;
                    let mut first_mismatch = None;
                    for c in &e.checks {
                        let mut bytes = vec![0; c.bytes.len()];
                        self.validation_bytes
                            .set(self.validation_bytes.get() + bytes.len() as u64);
                        match read(c.address, &mut bytes) {
                            Err(error) => {
                                valid = false;
                                read_error.get_or_insert_with(|| {
                                    format!("unreadable check at {:#x}: {error}", c.address)
                                });
                            }
                            Ok(()) if !c.matches(&bytes) => {
                                valid = false;
                                first_mismatch.get_or_insert_with(|| {
                                    format!(
                                        "check at {:#x}, expected {:02x?}, observed {:02x?}, mask {:?}",
                                        c.address, c.bytes, bytes, c.mask
                                    )
                                });
                            }
                            Ok(()) => (),
                        }
                    }
                    if !valid {
                        if let Some(error) = read_error {
                            self.issue(
                                "validation_read",
                                format!("{} evidence {}; {}", e.category, index, error),
                            );
                        } else {
                            self.record_drift(
                                "reference_changed",
                                format!(
                                    "{} evidence {}; {}",
                                    e.category,
                                    index,
                                    first_mismatch.unwrap_or_else(|| {
                                        "process identity validation failed".into()
                                    })
                                ),
                            );
                        }
                    }
                    valid
                });
                result.push(json!({"physical":pa,"category":e.category,"reference":e.detail,"same_fields":(!e.checks.is_empty()).then_some(valid),"observed_ns":now()}));
            }
        }
        self.validation_ns
            .set(self.validation_ns.get() + now() - started);
        json!(result)
    }
    pub fn finish(&self) -> Value {
        let read_count = self.visited.borrow().len();
        let released_count = self
            .released
            .borrow()
            .difference(&self.visited.borrow())
            .count();
        let omitted = self.pages.len().saturating_sub(read_count + released_count);
        json!({"complete":self.issue_count.get()==0&&omitted==0,"candidate_pages":self.pages.len(),
            "read_candidate_pages":read_count,"released_before_read_pages":released_count,
            "unread_candidate_pages":omitted,"issue_count":self.issue_count.get(),"issues":*self.issues.borrow(),
            "live_drift_count":self.drift_count.get(),"live_drift":*self.drift.borrow(),
            "validation_requested_bytes":self.validation_bytes.get(),"validation_ns":self.validation_ns.get(),
            "consistency":"Selected pointer/length fields checked around reads. Live, non-atomic drift is recorded separately from collector errors."})
    }
    #[allow(clippy::too_many_arguments)]
    pub fn discover(
        core: &File,
        segs: &[Segment],
        ram: &[(u64, u64)],
        symbols: &Value,
        btf_bytes: Result<Vec<u8>>,
        deadline: u64,
        code_targets: &[crate::code_pages::CowTarget],
    ) -> Self {
        let started = now();
        let mut result = Self::default();
        let run = (|| -> Result<Value> {
            let btf = Btf::parse(btf_bytes?)?;
            let symbol = |name: &str| {
                symbols[name]
                    .as_u64()
                    .filter(|&v| v != 0)
                    .ok_or_else(|| format!("resource symbol unavailable: {name}"))
            };
            let mut live = Live {
                core,
                segs,
                ram,
                deadline,
                read_limit: MAX_READ_BYTES,
                read_bytes: Cell::new(0),
                calls: Cell::new(0),
                root: 0,
                levels: 4,
            };
            let root = ["init_top_pgt", "init_level4_pgt", "swapper_pg_dir"]
                .iter()
                .find_map(|n| symbol(n).ok())
                .ok_or("kernel page-table root unavailable")?;
            live.root = live.physical(root)?;
            if let Some(va) = ["__pgtable_l5_enabled", "pgtable_l5_enabled"]
                .iter()
                .find_map(|n| symbol(n).ok())
                && live.uint(va, 4)? != 0
            {
                live.levels = 5;
            }
            let vmemmap = live.uint(symbol("vmemmap_base")?, 8)?;
            let page_size = btf.size("page")? as u64;
            if !(32..=4096).contains(&page_size) {
                return Err("invalid BTF page size".into());
            }
            let mut scan = Scan {
                btf,
                live,
                plan: &mut result,
                fields: RefCell::new(HashMap::new()),
                vmemmap,
                page_size,
                files: BTreeSet::new(),
                tables: BTreeSet::new(),
                tasks: 0,
                thread_tasks: BTreeSet::new(),
                fd_refs: 0,
                sockets: 0,
                skbs: 0,
                policy_truncations: 0,
                task_identity: Value::Null,
                task_checks: Vec::new(),
                mm_owners: BTreeMap::new(),
                cache: cache::CacheState::default(),
                code_targets: code_targets.to_vec(),
            };
            if let Err(e) = scan.tasks(symbol("init_task")?) {
                scan.plan.issue("traversal", e);
            }
            scan.capture_cache();
            Ok(
                json!({"file_cache":scan.cache.summary(),"tasks_examined":scan.tasks,"threads_examined":scan.thread_tasks.len(),"unique_fd_tables":scan.tables.len(),"address_spaces_indexed":scan.mm_owners.len(),"fd_references_examined":scan.fd_refs,
                "unique_files":scan.files.len(),"sockets_examined":scan.sockets,"skbs_examined":scan.skbs,
                "policy_window_truncations":scan.policy_truncations,
                "discovery_requested_bytes":scan.live.read_bytes.get(),"discovery_read_calls":scan.live.calls.get()}),
            )
        })();
        let stats = match run {
            Ok(v) => v,
            Err(e) => {
                result.issue("discovery", e);
                Value::Null
            }
        };
        result.summary = json!({"policy":"referenced_socket_queues_and_unlinked_cache_v5","begin_ns":started,"end_ns":now(),"stats":stats,
            "candidate_pages":result.pages.len(),"references":result.evidence.len(),"issues_at_discovery":result.issue_count.get(),"drift_at_discovery":result.drift_count.get(),
            "limits":{"requested_metadata_bytes":MAX_READ_BYTES,"candidate_pages":MAX_CANDIDATES,"references":MAX_REFS,"queue_payload_bytes":QUEUE_BYTES,"process_leaders":16384,"threads_per_group":4096,"threads":MAX_THREAD_TASKS},
            "scope":"Node-wide process leaders and threads, including separate FD tables. Shared FD tables are deduplicated. Socket receive/write queues plus TCP retransmit/out-of-order trees, plus resident unlinked regular files (i_nlink == 0, including memfd/O_TMPFILE) via open FDs or pure-BTF shared memfd VMAs, and backing cache pages for discovered executable COW pages. Ordinary linked files (i_nlink != 0) are excluded.",
            "window_policy":"64KiB per queue. Bytes beyond this per-queue limit are explicit policy truncations, not all-content coverage.",
            "btf_required":true});
        result
    }
}
struct Scan<'a, 'p> {
    mm_owners: BTreeMap<u64, Vec<MmOwner>>,
    cache: cache::CacheState,
    code_targets: Vec<crate::code_pages::CowTarget>,
    btf: Btf,
    live: Live<'a>,
    plan: &'p mut Resources,
    fields: RefCell<HashMap<(&'static str, &'static str), Field>>,
    vmemmap: u64,
    page_size: u64,
    files: BTreeSet<u64>,
    tables: BTreeSet<u64>,
    tasks: usize,
    thread_tasks: BTreeSet<u64>,
    fd_refs: usize,
    sockets: usize,
    skbs: usize,
    policy_truncations: usize,
    task_identity: Value,
    task_checks: Vec<Check>,
}
struct MmOwner {
    task: u64,
    pid: u64,
    start_time_ns: u64,
    checks: Vec<Check>,
}
fn task_boottime_field(btf: &Btf) -> Result<(&'static str, Field)> {
    let (name, field) = match btf.field("task_struct", "start_boottime") {
        Ok(field) => ("start_boottime", field),
        Err(error) if error.to_string() == "BTF member unavailable: start_boottime" => (
            "real_start_time",
            btf.field("task_struct", "real_start_time")?,
        ),
        Err(error) => return Err(error),
    };
    // Older kernels call the boot-based nanosecond value real_start_time.
    // start_time uses the monotonic clock and is not a substitute.
    if field.size != 8 || field.bits != 0 {
        return Err("unsupported task boot-time scalar layout".into());
    }
    Ok((name, field))
}
impl Scan<'_, '_> {
    fn field(&self, t: &'static str, n: &'static str) -> Result<Field> {
        if let Some(f) = self.fields.borrow().get(&(t, n)) {
            return Ok(*f);
        }
        let f = self.btf.field(t, n)?;
        self.fields.borrow_mut().insert((t, n), f);
        Ok(f)
    }
    fn value(&self, a: u64, t: &'static str, n: &'static str) -> Result<u64> {
        let f = self.field(t, n)?;
        f.value(
            &self
                .live
                .read(a.checked_add(f.offset).ok_or("field overflow")?, f.size)?,
        )
    }
    fn off(&self, t: &'static str, n: &'static str) -> Result<u64> {
        Ok(self.field(t, n)?.offset)
    }
    fn check(&self, a: u64, t: &'static str, n: &'static str) -> Result<Check> {
        let f = self.field(t, n)?;
        if f.size > 256 {
            return Err("signature field too large".into());
        }
        let address = a + f.offset;
        Ok(Check {
            address,
            bytes: self.live.read(address, f.size)?,
            mask: None,
        })
    }
    fn expect(&self, a: u64, t: &'static str, n: &'static str, value: u64) -> Result<Check> {
        let check = self.check(a, t, n)?;
        if self.field(t, n)?.value(&check.bytes)? != value {
            return Err("reference changed during discovery".into());
        }
        Ok(check)
    }
    fn add(
        &mut self,
        pa: u64,
        n: u64,
        category: &'static str,
        mut detail: Value,
        checks: Vec<Check>,
    ) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        if n > QUEUE_BYTES + PAGE {
            return Err("resource interval exceeds bound".into());
        }
        let end = pa.checked_add(n).ok_or("resource overflow")?;
        let mut pages = Vec::new();
        let mut p = pa / PAGE * PAGE;
        while p < end {
            if !self.live.ram.iter().any(|&(a, b)| a <= p && p + PAGE <= b) {
                return Err("resource page outside RAM".into());
            }
            pages.push(p);
            p += PAGE;
        }
        if self.plan.evidence.len() >= MAX_REFS
            || self.plan.pages.len()
                + pages
                    .iter()
                    .filter(|p| !self.plan.pages.contains_key(p))
                    .count()
                > MAX_CANDIDATES
        {
            return Err("resource candidate/reference budget".into());
        }
        if category == "file_cache" {
            self.cache.reserve(&pages)?;
        }
        let i = self.plan.evidence.len();
        detail["physical_start"] = json!(pa);
        detail["bytes"] = json!(n);
        self.plan.evidence.push(Evidence {
            category,
            detail,
            checks,
        });
        for p in pages {
            self.plan.pages.entry(p).or_default().push(i);
        }
        Ok(())
    }
    fn add_va(
        &mut self,
        va: u64,
        n: u64,
        category: &'static str,
        detail: Value,
        checks: Vec<Check>,
    ) -> Result<()> {
        let mut done = 0;
        while done < n {
            let take = (PAGE - (va + done) % PAGE).min(n - done);
            let pa = self.live.physical(va + done)?;
            let mut part = detail.clone();
            part["virtual_address"] = json!(va + done);
            part["bytes"] = json!(take);
            if let Some(offset) = detail["skb_offset"].as_u64() {
                part["skb_offset"] = json!(offset + done);
            }
            self.add(pa, take, category, part, checks.clone())?;
            done += take;
        }
        Ok(())
    }
    fn metadata(&mut self, va: u64, t: &str, category: &'static str, detail: Value) -> Result<()> {
        let size = self.btf.size(t)? as u64;
        if size > 16384 {
            return Err("resource metadata size bound".into());
        }
        self.add_va(
            va,
            size,
            category,
            metadata_owner(detail, &self.task_identity),
            self.task_checks.clone(),
        )
    }
    fn tasks(&mut self, init: u64) -> Result<()> {
        let tasks_off = self.off("task_struct", "tasks")?;
        let head = init + tasks_off;
        let mut at = self.live.uint(head, 8)?;
        let mut seen = BTreeSet::new();
        while at != head {
            if self.thread_tasks.len() >= MAX_THREAD_TASKS {
                return Err("global thread traversal limit".into());
            }
            if !seen.insert(at) || self.tasks >= 16384 {
                return Err("task traversal limit/cycle".into());
            }
            self.tasks += 1;
            let task = at.checked_sub(tasks_off).ok_or("task address underflow")?;
            let pid = self.value(task, "task_struct", "pid")?;
            if let Err(e) = self.index_mm_owner(task, pid) {
                self.plan.issue_or_drift("mm_owner_index", e);
            }
            // Preserve leader evidence even if the optional thread list is
            // unreadable or changes while the collector walks it.
            if let Err(e) = self.task_files(task) {
                self.plan.issue_or_drift("task_files", e);
            }
            if let Err(e) = self.threads(task) {
                self.plan.issue_or_drift("threads", e);
            }
            at = self.live.uint(at, 8)?;
        }
        Ok(())
    }
    fn index_mm_owner(&mut self, task: u64, pid: u64) -> Result<()> {
        let mm = self.value(task, "task_struct", "mm")?;
        if mm == 0 {
            return Ok(());
        }
        let start_time_ns = self.value(task, "task_struct", "start_time")?;
        let checks = vec![
            self.expect(task, "task_struct", "pid", pid)?,
            self.expect(task, "task_struct", "start_time", start_time_ns)?,
            self.expect(task, "task_struct", "mm", mm)?,
        ];
        self.mm_owners.entry(mm).or_default().push(MmOwner {
            task,
            pid,
            start_time_ns,
            checks,
        });
        Ok(())
    }
    fn threads(&mut self, leader: u64) -> Result<()> {
        let signal = self.value(leader, "task_struct", "signal")?;
        if signal == 0 {
            return Err("thread group signal unavailable".into());
        }
        let tgid = self.value(leader, "task_struct", "tgid")?;
        let head = signal
            .checked_add(self.off("signal_struct", "thread_head")?)
            .ok_or("thread head overflow")?;
        let offset = self.off("task_struct", "thread_node")?;
        let mut at = self.live.uint(head, 8)?;
        let mut seen = BTreeSet::new();
        while at != head {
            if !seen.insert(at) || seen.len() > 4096 {
                return Err("thread traversal limit/cycle".into());
            }
            let task = at.checked_sub(offset).ok_or("thread address underflow")?;
            if self.value(task, "task_struct", "signal")? != signal
                || self.value(task, "task_struct", "tgid")? != tgid
            {
                return Err("thread group identity changed".into());
            }
            if !self.thread_tasks.contains(&task) && self.thread_tasks.len() >= MAX_THREAD_TASKS {
                return Err("global thread traversal limit".into());
            }
            if let Err(e) = self.task_files(task) {
                self.plan.issue_or_drift("thread_files", e);
            }
            at = self.live.uint(at, 8)?;
        }
        Ok(())
    }
    fn task_files(&mut self, task: u64) -> Result<()> {
        if self.thread_tasks.contains(&task) {
            return Ok(());
        }
        if self.thread_tasks.len() >= MAX_THREAD_TASKS {
            return Err("global thread traversal limit".into());
        }
        self.thread_tasks.insert(task);
        let pid = self.value(task, "task_struct", "pid")?;
        let tgid = self.value(task, "task_struct", "tgid")?;
        let boot_field = task_boottime_field(&self.btf).ok().map(|(name, _)| name);
        let boot = boot_field
            .map(|name| self.value(task, "task_struct", name))
            .transpose()?;
        let files = self.value(task, "task_struct", "files")?;
        let start = self.value(task, "task_struct", "start_time")?;
        self.task_identity = json!({"task":task,"pid":pid,"tgid":tgid,"start_time_ns":start,"start_boottime_ns":boot,"start_boottime_field":boot_field});
        self.task_checks = vec![
            self.expect(task, "task_struct", "pid", pid)?,
            self.expect(task, "task_struct", "tgid", tgid)?,
            self.expect(task, "task_struct", "start_time", start)?,
            self.expect(task, "task_struct", "files", files)?,
        ];
        if let Some(boot) = boot {
            self.task_checks.push(self.expect(
                task,
                "task_struct",
                boot_field.ok_or("task boot-time field unavailable")?,
                boot,
            )?);
        }
        if let Err(e) = self.queue_memfd_discovery(task) {
            self.plan.issue_or_drift("mm_vma_seed", e);
        }
        if files != 0
            && self.tables.insert(files)
            && let Err(e) = self.fdtable(files, pid)
        {
            self.plan.issue_or_drift("fdtable", e);
        }
        Ok(())
    }
    fn fdtable(&mut self, files: u64, pid: u64) -> Result<()> {
        let table = self.value(files, "files_struct", "fdt")?;
        let max = self.value(table, "fdtable", "max_fds")?;
        if max > 262144 {
            return Err("FD number-space limit".into());
        }
        let array = self.value(table, "fdtable", "fd")?;
        let bitmap = self.value(table, "fdtable", "open_fds")?;
        let bits = self.live.read(bitmap, max.div_ceil(64) as usize * 8)?;
        for (word, bytes) in bits.as_chunks::<8>().0.iter().enumerate() {
            let mut bits = u64::from_le_bytes(*bytes);
            while bits != 0 {
                if self.fd_refs >= MAX_REFS {
                    return Err("FD reference limit".into());
                }
                self.fd_refs += 1;
                let bit = bits.trailing_zeros() as u64;
                bits &= bits - 1;
                let fd = word as u64 * 64 + bit;
                if fd >= max {
                    continue;
                }
                let file = self.live.uint(array + fd * 8, 8)?;
                if file == 0 {
                    continue;
                }
                if self.files.insert(file)
                    && let Err(e) = self.file(
                        file,
                        pid,
                        json!({"kind":"fd","fd":fd,"files":files,"table":table,"array":array}),
                    )
                {
                    self.files.remove(&file);
                    self.plan.issue_or_drift("file", e);
                }
            }
        }
        Ok(())
    }
    fn file(&mut self, file: u64, pid: u64, origin: Value) -> Result<()> {
        let inode = self.value(file, "file", "f_inode")?;
        if inode != 0 {
            match self.value(inode, "inode", "i_mode")? & 0xf000 {
                0xc000 => self.socket(file, pid, origin)?,
                0x8000 => self.queue_file_cache(file, origin)?,
                _ => {}
            }
        }
        Ok(())
    }
    fn fd_checks(&self, file: u64, origin: &Value) -> Result<Vec<Check>> {
        let number = |key: &str| origin[key].as_u64().ok_or("missing socket FD origin");
        let files = number("files")?;
        let table = number("table")?;
        let array = number("array")?;
        let fd = number("fd")?;
        let max = self.value(table, "fdtable", "max_fds")?;
        if fd >= max || max > 262144 {
            return Err("socket FD bounds changed".into());
        }
        let bitmap = self.value(table, "fdtable", "open_fds")?;
        let address = array
            .checked_add(fd.checked_mul(8).ok_or("FD offset overflow")?)
            .ok_or("FD slot overflow")?;
        let slot = Check {
            address,
            bytes: self.live.read(address, 8)?,
            mask: None,
        };
        if slot.bytes != file.to_le_bytes() {
            return Err("socket FD changed".into());
        }
        let address = bitmap
            .checked_add((fd / 64) * 8)
            .ok_or("FD bitmap overflow")?;
        let open = Check {
            address,
            bytes: self.live.read(address, 8)?,
            mask: Some(1 << (fd % 64)),
        };
        if u64::from_le_bytes(open.bytes.as_slice().try_into()?) & open.mask.unwrap() == 0 {
            return Err("socket FD closed".into());
        }
        Ok(vec![
            self.expect(files, "files_struct", "fdt", table)?,
            self.expect(table, "fdtable", "fd", array)?,
            self.expect(table, "fdtable", "max_fds", max)?,
            self.expect(table, "fdtable", "open_fds", bitmap)?,
            slot,
            open,
        ])
    }
    fn socket(&mut self, file: u64, pid: u64, origin: Value) -> Result<()> {
        if self.sockets >= 4096 {
            return Err("socket limit".into());
        }
        self.sockets += 1;
        let socket = self.value(file, "file", "private_data")?;
        if socket == 0 {
            return Ok(());
        }
        if self.value(socket, "socket", "file")? != file {
            return Err("socket file backlink mismatch".into());
        }
        let sk = self.value(socket, "socket", "sk")?;
        if sk == 0 {
            return Ok(());
        }
        if self.value(sk, "sock", "sk_socket")? != socket {
            return Err("sock socket backlink mismatch".into());
        }
        let family = self.value(sk, "sock", "__sk_common.skc_family")?;
        let proto = self.value(sk, "sock", "sk_protocol")?;
        if !matches!(family, 1 | 2 | 10) {
            return Ok(());
        }
        let tcp = matches!(family, 2 | 10) && proto == 6;
        let udp = matches!(family, 2 | 10) && proto == 17;
        let mut queues = vec![("sock", "sk_receive_queue"), ("sock", "sk_write_queue")];
        // UDP MSG_PEEK can move still-unread datagrams to this private queue.
        // Resolve through running-kernel BTF; an absent field is a reported error.
        if udp {
            queues.push(("udp_sock", "reader_queue"));
        }
        let mut nonempty = false;
        for &(typ, name) in &queues {
            let queue = sk + self.off(typ, name)?;
            let first = self.value(queue, "sk_buff_head", "next")?;
            nonempty |= first != 0 && first != queue;
        }
        if tcp {
            for (typ, name) in [
                ("sock", "tcp_rtx_queue"),
                ("tcp_sock", "out_of_order_queue"),
            ] {
                let root = sk + self.off(typ, name)?;
                nonempty |= self.value(root, "rb_root", "rb_node")? != 0;
            }
        }
        // Empty queues need no extra payload or duplicate metadata evidence.
        if !nonempty {
            return Ok(());
        }
        let mut checks = self.fd_checks(file, &origin)?;
        checks.extend([
            self.expect(file, "file", "private_data", socket)?,
            self.expect(socket, "socket", "file", file)?,
            self.expect(socket, "socket", "sk", sk)?,
            self.expect(sk, "sock", "sk_socket", socket)?,
        ]);
        // Every network evidence record, including metadata and fragments,
        // inherits the FD-to-socket chain. Restore task context on every error.
        let task_checks = self.task_checks.clone();
        self.task_checks.extend(checks);
        let result = (|| -> Result<()> {
            let detail = json!({"pid":pid,"process":self.task_identity,"file":file,"socket":socket,"sock":sk,"family":family,"protocol":proto,"origin":origin});
            self.metadata(file, "file", "network", detail.clone())?;
            self.metadata(socket, "socket", "network", detail.clone())?;
            self.metadata(sk, "sock", "network", detail.clone())?;
            if udp {
                self.metadata(sk, "udp_sock", "network", detail.clone())?;
            }
            for (typ, name) in queues {
                let queue_result = (|| -> Result<()> {
                    let queue = sk + self.off(typ, name)?;
                    let mut at = self.value(queue, "sk_buff_head", "next")?;
                    let mut seen = BTreeSet::new();
                    let mut left = QUEUE_BYTES;
                    while at != 0 && at != queue {
                        if !seen.insert(at) || seen.len() > 256 {
                            return Err("skb queue cycle/node limit".into());
                        }
                        self.skb(at, &detail, name, &mut left, 0)?;
                        at = self.value(at, "sk_buff", "next")?;
                        if left == 0 {
                            if at != queue {
                                self.policy_truncations += 1;
                            }
                            break;
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = queue_result {
                    self.plan.issue(name, error);
                }
            }
            if tcp {
                self.metadata(sk, "tcp_sock", "network", detail.clone())?;
                for (typ, name) in [
                    ("sock", "tcp_rtx_queue"),
                    ("tcp_sock", "out_of_order_queue"),
                ] {
                    let queue_result = (|| -> Result<()> {
                        let root = sk + self.off(typ, name)?;
                        self.retain_skb_tree(root, &detail, name)
                    })();
                    if let Err(error) = queue_result {
                        self.plan.issue(name, error);
                    }
                }
            }
            Ok(())
        })();
        self.task_checks = task_checks;
        result
    }
    fn retain_skb_tree(&mut self, root: u64, detail: &Value, name: &'static str) -> Result<()> {
        let mut todo = vec![self.value(root, "rb_root", "rb_node")?];
        let mut seen = BTreeSet::new();
        let offset = self.off("sk_buff", "rbnode")?;
        let mut left = QUEUE_BYTES;
        while let Some(node) = todo.pop() {
            if node == 0 {
                continue;
            }
            if seen.len() >= 256 {
                return Err("TCP skb tree node limit".into());
            }
            if !seen.insert(node) {
                self.plan
                    .issue(name, format!("TCP skb tree cycle at {node:#x}"));
                continue;
            }
            let result = node
                .checked_sub(offset)
                .ok_or_else(|| "skb rbnode underflow".into())
                .and_then(|skb| self.skb(skb, detail, name, &mut left, 0));
            if let Err(error) = result {
                self.plan
                    .issue(name, format!("skb node {node:#x}: {error}"));
            }
            // Child metadata and payload are independent observations. A bad
            // buffer or one unreadable child must not discard the other branch.
            for field in ["rb_right", "rb_left"] {
                match self.value(node, "rb_node", field) {
                    Ok(child) => todo.push(child),
                    Err(error) => self.plan.issue(name, format!("{node:#x}.{field}: {error}")),
                }
            }
            if left == 0 {
                if todo.iter().any(|&node| node != 0) {
                    self.policy_truncations += 1;
                }
                break;
            }
        }
        Ok(())
    }
    fn skb(
        &mut self,
        skb: u64,
        owner: &Value,
        queue: &str,
        left: &mut u64,
        depth: usize,
    ) -> Result<()> {
        if depth > 4 || self.skbs >= 8192 {
            return Err("skb recursion/global node limit".into());
        }
        self.skbs += 1;
        let head = self.value(skb, "sk_buff", "head")?;
        let data = self.value(skb, "sk_buff", "data")?;
        let length = self.value(skb, "sk_buff", "len")?;
        let nonlinear = self.value(skb, "sk_buff", "data_len")?;
        let tail = self.value(skb, "sk_buff", "tail")?;
        let end = self.value(skb, "sk_buff", "end")?;
        if nonlinear > length
            || tail > end
            || end > 16 * 1024 * 1024
            || data < head
            || data
                .checked_add(length - nonlinear)
                .is_none_or(|v| head.checked_add(tail).is_none_or(|limit| v > limit))
        {
            return Err("skb data bounds".into());
        }
        let mut checks = vec![
            self.expect(skb, "sk_buff", "head", head)?,
            self.expect(skb, "sk_buff", "data", data)?,
            self.expect(skb, "sk_buff", "len", length)?,
            self.expect(skb, "sk_buff", "data_len", nonlinear)?,
            self.expect(skb, "sk_buff", "end", end)?,
        ];
        checks.extend(self.task_checks.clone());
        let mut detail = owner.clone();
        detail["skb"] = json!(skb);
        detail["queue"] = json!(queue);
        detail["skb_bytes"] = json!(length);
        detail["role"] = json!("network_bytes");
        detail["skb_offset"] = json!(0);
        self.metadata(
            skb,
            "sk_buff",
            "network",
            json!({"skb":skb,"role":"skb_metadata"}),
        )?;
        let available = *left;
        let linear = (length - nonlinear).min(*left);
        self.add_va(data, linear, "network", detail.clone(), checks.clone())?;
        *left -= linear;
        let shinfo = head.checked_add(end).ok_or("skb shared info overflow")?;
        self.metadata(
            shinfo,
            "skb_shared_info",
            "network",
            json!({"skb":skb,"shared_info":shinfo,"role":"shared_info_metadata"}),
        )?;
        let frags = self.field("skb_shared_info", "frags")?;
        let (frag_type, capacity) = self.btf.array(frags.type_id)?;
        let stride = self.btf.size_id(frag_type)?;
        let nr = self.value(shinfo, "skb_shared_info", "nr_frags")? as usize;
        if nr > capacity || nr > 64 {
            return Err("skb fragment count".into());
        }
        let page_field = self
            .btf
            .field_id(frag_type, "bv_page")
            .or_else(|_| self.btf.field_id(frag_type, "netmem"))?;
        let len_field = self
            .btf
            .field_id(frag_type, "bv_len")
            .or_else(|_| self.btf.field_id(frag_type, "len"))?;
        let off_field = self
            .btf
            .field_id(frag_type, "bv_offset")
            .or_else(|_| self.btf.field_id(frag_type, "offset"))?;
        let mut accounted = 0;
        for i in 0..nr {
            if *left == 0 {
                self.policy_truncations += 1;
                break;
            }
            let at = shinfo + frags.offset + (i * stride) as u64;
            let raw = self.live.read(at, stride)?;
            let get = |f: Field| -> Result<u64> {
                let off = f.offset as usize;
                f.value(raw.get(off..off + f.size).ok_or("fragment field bounds")?)
            };
            let page = get(page_field)?;
            let size = get(len_field)?;
            let offset = get(off_field)?;
            if page & 1 != 0
                || page < self.vmemmap
                || !(page - self.vmemmap).is_multiple_of(self.page_size)
            {
                return Err("unsupported netmem/non-page fragment".into());
            }
            accounted += size;
            if accounted > nonlinear {
                return Err("fragments exceed skb nonlinear length".into());
            }
            let pa = ((page - self.vmemmap) / self.page_size)
                .checked_mul(PAGE)
                .and_then(|n| n.checked_add(offset))
                .ok_or("fragment PFN overflow")?;
            let take = size.min(*left);
            let mut d = detail.clone();
            d["skb_offset"] = json!(length - nonlinear + accounted - size);
            d["fragment"] = json!(i);
            d["page"] = json!(page);
            d["fragment_offset"] = json!(offset);
            d["bytes"] = json!(take);
            let mut c = checks.clone();
            c.push(Check {
                address: at,
                bytes: raw,
                mask: None,
            });
            self.add(pa, take, "network", d, c)?;
            *left -= take;
            self.metadata(
                page,
                "page",
                "network",
                json!({"page":page,"role":"fragment_page_metadata"}),
            )?;
        }
        let mut child = self.value(shinfo, "skb_shared_info", "frag_list")?;
        let mut seen = BTreeSet::new();
        while child != 0 && *left != 0 {
            if !seen.insert(child) || seen.len() > 64 {
                return Err("skb frag_list cycle/limit".into());
            }
            accounted += self.value(child, "sk_buff", "len")?;
            if accounted > nonlinear {
                return Err("frag_list exceeds skb nonlinear length".into());
            }
            self.skb(child, owner, queue, left, depth + 1)?;
            child = self.value(child, "sk_buff", "next")?;
        }
        if child != 0 || length > available {
            self.policy_truncations += 1;
        } else if *left != 0 && accounted != nonlinear {
            return Err("skb nonlinear coverage incomplete".into());
        }
        Ok(())
    }
}
