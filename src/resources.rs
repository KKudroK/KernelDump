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
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REFS: usize = 16384;
const MAX_CANDIDATES: usize = 8192;
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
        assert_eq!(r.finish()["complete"], false);
        assert_eq!(r.finish()["unread_candidate_pages"], 0);
        let stable = candidate();
        stable.witness(PAGE, 2 * PAGE, true, |_, data| {
            data.copy_from_slice(&[1, 2, 3, 4]);
            Ok(())
        });
        assert_eq!(stable.finish()["complete"], true);
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
            None,
            &[],
        );
        assert_eq!(result.finish()["complete"], false);
        assert_eq!(result.summary()["issues_at_discovery"], 1);
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
    // For an open_fds word only the target FD bit is part of this reference.
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
    pod: Option<crate::pod_scope::PodScope>,
    pages: BTreeMap<u64, Vec<usize>>,
    evidence: Vec<Evidence>,
    summary: Value,
    issues: RefCell<Vec<Value>>,
    issue_count: Cell<u64>,
    visited: RefCell<BTreeSet<u64>>,
    validation_bytes: Cell<u64>,
    validation_ns: Cell<u64>,
}
impl Resources {
    fn issue(&self, stage: &str, e: impl ToString) {
        self.issue_count.set(self.issue_count.get() + 1);
        let mut v = self.issues.borrow_mut();
        if v.len() < 32 {
            v.push(json!({"stage":stage,"error":e.to_string()}));
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
        let mut identities = HashMap::new();
        for (&pa, indices) in self.pages.range(a..b) {
            if after {
                self.visited.borrow_mut().insert(pa);
            }
            for &index in indices {
                let e = &self.evidence[index];
                let valid = *checked.entry(index).or_insert_with(|| {
                    if self.validation_ns.get() + now() - started > 500_000_000
                        || self.validation_bytes.get() > 16 * 1024 * 1024
                    {
                        self.issue("validation_limit", "resource reference validation budget");
                        return false;
                    }
                    let mut valid = if let Some(scope) = &self.pod {
                        let id = e.detail["process"]["pid"].as_u64().unwrap_or(0) as u32;
                        let boot = e.detail["process"]["start_boottime_ns"]
                            .as_u64()
                            .unwrap_or(0);
                        *identities
                            .entry(id)
                            .or_insert_with(|| scope.validate_thread(id, boot).is_ok())
                    } else {
                        true
                    };
                    for c in &e.checks {
                        let mut bytes = vec![0; c.bytes.len()];
                        self.validation_bytes
                            .set(self.validation_bytes.get() + bytes.len() as u64);
                        if read(c.address, &mut bytes).is_err() || !c.matches(&bytes) {
                            valid = false;
                        }
                    }
                    if !valid {
                        self.issue(
                            "reference_changed",
                            format!("{} evidence {}", e.category, index),
                        );
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
        let omitted = self.pages.len() - self.visited.borrow().len();
        json!({"complete":self.issue_count.get()==0&&omitted==0,"candidate_pages":self.pages.len(),"read_candidate_pages":self.visited.borrow().len(),
            "pod_identity_validation":self.pod.as_ref().map(|p|p.validation_stats()),
            "unread_candidate_pages":omitted,"issue_count":self.issue_count.get(),"issues":*self.issues.borrow(),
            "validation_requested_bytes":self.validation_bytes.get(),"validation_ns":self.validation_ns.get(),
            "consistency":"Selected pointer/length fields checked around reads. Live, non-atomic and subject to ABA or changes in payload bytes."})
    }
    pub fn discover(
        core: &File,
        segs: &[Segment],
        ram: &[(u64, u64)],
        symbols: &Value,
        btf_bytes: Result<Vec<u8>>,
        deadline: u64,
        pod: Option<&crate::pod_scope::PodScope>,
        code_targets: &[(u32, u64, u64, u64)],
    ) -> Self {
        let started = now();
        let mut result = Self::default();
        result.pod = pod.cloned();
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
            {
                if live.uint(va, 4)? != 0 {
                    live.levels = 5;
                }
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
                fd_refs: 0,
                sockets: 0,
                skbs: 0,
                policy_truncations: 0,
                task_identity: Value::Null,
                task_checks: Vec::new(),
                pod: pod.cloned(),
                target_seen: BTreeSet::new(),
                cache: cache::CacheState::default(),
                code_targets: code_targets.to_vec(),
            };
            if let Err(e) = scan.tasks(symbol("init_task")?) {
                scan.plan.issue("traversal", e);
            }
            if let Some(scope) = pod {
                for tid in scope
                    .threads
                    .keys()
                    .filter(|id| !scan.target_seen.contains(id))
                {
                    scan.plan.issue("pod_thread_not_observed", tid);
                }
            }
            scan.capture_cache();
            Ok(
                json!({"file_cache":scan.cache.summary(),"tasks_examined":scan.tasks,"fd_references_examined":scan.fd_refs,
                "unique_files":scan.files.len(),"sockets_examined":scan.sockets,"skbs_examined":scan.skbs,
                "target_threads_observed":scan.target_seen.len(),
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
        result.summary = json!({"policy":"referenced_socket_queues_and_pod_cache_v4","pod_uid":pod.map(|p|&p.uid),"begin_ns":started,"end_ns":now(),"stats":stats,
            "candidate_pages":result.pages.len(),"references":result.evidence.len(),"issues_at_discovery":result.issue_count.get(),
            "limits":{"requested_metadata_bytes":MAX_READ_BYTES,"candidate_pages":MAX_CANDIDATES,"references":MAX_REFS,"queue_payload_bytes":QUEUE_BYTES},
            "scope":"Selected Pod census threads including separate FD tables when --pod is supplied; otherwise process-leader FD references. Socket receive/write queues plus TCP retransmit/out-of-order trees. With Pod scope, bounded resident small shmem/unlinked-file cache and cache pages corresponding to discovered executable COW pages are considered after sockets. No general file-cache sweep or full socket history.",
            "window_policy":"64KiB per queue. Bytes beyond this per-queue limit are explicit policy truncations, not all-content coverage.",
            "btf_required":true});
        result
    }
}
struct Scan<'a, 'p> {
    pod: Option<crate::pod_scope::PodScope>,
    target_seen: BTreeSet<u32>,
    cache: cache::CacheState,
    code_targets: Vec<(u32, u64, u64, u64)>,
    btf: Btf,
    live: Live<'a>,
    plan: &'p mut Resources,
    fields: RefCell<HashMap<(&'static str, &'static str), Field>>,
    vmemmap: u64,
    page_size: u64,
    files: BTreeSet<u64>,
    tables: BTreeSet<u64>,
    tasks: usize,
    fd_refs: usize,
    sockets: usize,
    skbs: usize,
    policy_truncations: usize,
    task_identity: Value,
    task_checks: Vec<Check>,
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
            if !seen.insert(at) || self.tasks >= 4096 {
                return Err("task traversal limit/cycle".into());
            }
            self.tasks += 1;
            let task = at.checked_sub(tasks_off).ok_or("task address underflow")?;
            let pid = self.value(task, "task_struct", "pid")?;
            if let Some(scope) = &self.pod {
                if scope.processes.contains_key(&(pid as u32)) {
                    if let Err(e) = self.threads(task) {
                        self.plan.issue("pod_threads", e);
                    }
                }
            } else if let Err(e) = self.task_files(task) {
                self.plan.issue("task_files", e);
            }
            at = self.live.uint(at, 8)?;
        }
        Ok(())
    }
    fn threads(&mut self, leader: u64) -> Result<()> {
        let signal = self.value(leader, "task_struct", "signal")?;
        let head = signal + self.off("signal_struct", "thread_head")?;
        let offset = self.off("task_struct", "thread_node")?;
        let mut at = self.live.uint(head, 8)?;
        let mut seen = BTreeSet::new();
        while at != head {
            if !seen.insert(at) || seen.len() > 4096 {
                return Err("Pod thread traversal limit/cycle".into());
            }
            let task = at.checked_sub(offset).ok_or("thread address underflow")?;
            if self.value(task, "task_struct", "signal")? != signal {
                return Err("thread signal changed".into());
            }
            if let Err(e) = self.task_files(task) {
                self.plan.issue("pod_thread_files", e);
            }
            at = self.live.uint(at, 8)?;
        }
        Ok(())
    }
    fn task_files(&mut self, task: u64) -> Result<()> {
        let pid = self.value(task, "task_struct", "pid")?;
        let boot = if self.pod.is_some() {
            self.value(task, "task_struct", "start_boottime")?
        } else {
            0
        };
        if let Some(scope) = &self.pod {
            if !scope.threads.contains_key(&(pid as u32)) {
                return Ok(());
            }
            let id = scope.validate_thread(pid as u32, boot)?;
            if self.value(task, "task_struct", "tgid")? != id.tgid as u64 {
                return Err("target tgid changed".into());
            }
            self.target_seen.insert(pid as u32);
        }
        let files = self.value(task, "task_struct", "files")?;
        let start = self.value(task, "task_struct", "start_time")?;
        self.task_identity = json!({"task":task,"pid":pid,"start_time_ns":start,"start_boottime_ns":boot,"pod_uid":self.pod.as_ref().map(|p|&p.uid)});
        self.task_checks = vec![
            self.expect(task, "task_struct", "pid", pid)?,
            self.expect(task, "task_struct", "start_time", start)?,
            self.expect(task, "task_struct", "files", files)?,
        ];
        if self.pod.is_some() {
            self.task_checks
                .push(self.expect(task, "task_struct", "start_boottime", boot)?);
        }
        if self.pod.is_some() {
            self.queue_code_cache(task, pid as u32);
        }
        if files != 0 && self.tables.insert(files) {
            if let Err(e) = self.fdtable(files, pid) {
                self.plan.issue("fdtable", e);
            }
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
        for (word, bytes) in bits.chunks_exact(8).enumerate() {
            let mut bits = u64::from_le_bytes(bytes.try_into()?);
            while bits != 0 {
                if self.fd_refs >= 16384 {
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
                if self.files.insert(file) {
                    if let Err(e) = self.file(
                        file,
                        pid,
                        json!({"kind":"fd","fd":fd,"files":files,"table":table,"array":array}),
                    ) {
                        self.plan.issue("file", e);
                    }
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
                0x8000 if self.pod.is_some() => self.queue_file_cache(file, origin),
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
            }
            if tcp {
                self.metadata(sk, "tcp_sock", "network", detail.clone())?;
                for (typ, name) in [
                    ("sock", "tcp_rtx_queue"),
                    ("tcp_sock", "out_of_order_queue"),
                ] {
                    let root = sk + self.off(typ, name)?;
                    let mut todo = vec![self.value(root, "rb_root", "rb_node")?];
                    let mut seen = BTreeSet::new();
                    let mut left = QUEUE_BYTES;
                    while let Some(node) = todo.pop() {
                        if node == 0 {
                            continue;
                        }
                        if !seen.insert(node) || seen.len() > 256 {
                            return Err("TCP skb tree cycle/node limit".into());
                        }
                        let skb = node
                            .checked_sub(self.off("sk_buff", "rbnode")?)
                            .ok_or("skb rbnode underflow")?;
                        self.skb(skb, &detail, name, &mut left, 0)?;
                        todo.push(self.value(node, "rb_node", "rb_right")?);
                        todo.push(self.value(node, "rb_node", "rb_left")?);
                        if left == 0 {
                            if todo.iter().any(|&n| n != 0) {
                                self.policy_truncations += 1;
                            }
                            break;
                        }
                    }
                }
            }
            Ok(())
        })();
        self.task_checks = task_checks;
        result
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
            if page & 1 != 0 || page < self.vmemmap || (page - self.vmemmap) % self.page_size != 0 {
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
