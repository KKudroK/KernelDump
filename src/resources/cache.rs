//! Node-wide condition-based retention of resident cache pages; no file-content fault-in.
use super::*;

#[cfg(test)]
mod memfd_tests;

const MAX_JOBS: usize = 4096;
const MAX_PAGES: usize = 65_536;
const MAX_XA_NODES_PER_FILE: usize = 16_384;
const TMPFS_MAGIC: u64 = 0x01021994;
const MAX_NS: u64 = 5_000_000_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MAPLE_WALK_NODES: usize = 4096;
const MAX_VMAS_PER_MM: usize = 65_536;
const MAX_REVERSE_VMAS: usize = 256;

struct XaWalkCtx<'a> {
    file: u64,
    inode: u64,
    mapping: u64,
    size: u64,
    max_index: u64,
    origin: &'a Value,
    slots_offset: u64,
    seen_nodes: BTreeSet<u64>,
}

struct ValidatedFolio {
    page: u64,
    first: u64,
    count: u64,
    flags: u64,
    flag_mask: u64,
    checks: Vec<Check>,
}

#[derive(Clone, Debug, PartialEq)]
struct MemfdSeed {
    start: u64,
    end: u64,
    page_offset: u64,
    inode: u64,
}

struct Job {
    kind: JobKind,
    identity: Value,
    checks: Vec<Check>,
}
enum JobKind {
    Maps {
        task: u64,
        mm: u64,
    },
    Fd {
        file: u64,
        origin: Value,
    },
    Vma {
        task: u64,
        seed: MemfdSeed,
    },
    Cow {
        task: u64,
        va: u64,
        offset: u64,
        physical: u64,
    },
}
impl JobKind {
    fn group(&self) -> usize {
        match self {
            Self::Fd { .. } => 0,
            Self::Maps { .. } => 1,
            Self::Vma { .. } => 2,
            Self::Cow { .. } => 3,
        }
    }
}
#[derive(Default)]
pub(super) struct CacheState {
    pub(super) extended: bool,
    jobs: Vec<Job>,
    maps_jobs: Vec<Job>,
    maps_mms: BTreeSet<u64>,
    pages: BTreeSet<u64>,
    metadata: BTreeSet<u64>,
    seen: BTreeSet<(u64, u64)>,
    vma_seeds: BTreeSet<(u64, u64)>,
    /// Deduplicate by `(inode_va, file_offset / PAGE, cow_physical)` so forked workers sharing an executable mapping enqueue only one COW backing job.
    cow_seen: BTreeSet<(u64, u64, u64)>,
    memfd_mappings: BTreeSet<u64>,
    reverse_observations: Vec<Value>,
    queued: usize,
    queued_by_kind: [usize; 4],
    omitted: usize,
    excluded: usize,
    empty: usize,
    observations: Vec<Value>,
    hits: usize,
    misses: usize,
    duplicates: usize,
    elapsed: u64,
    bytes: u64,
    calls: u64,
}
impl CacheState {
    pub(super) fn with_extended(extended: bool) -> Self {
        Self {
            extended,
            ..Self::default()
        }
    }
    pub(super) fn reserve(&mut self, pages: &[u64]) -> Result<()> {
        if self.pages.len() + pages.iter().filter(|p| !self.pages.contains(p)).count() > MAX_PAGES {
            return Err("cache candidate-page safety limit".into());
        }
        self.pages.extend(pages);
        Ok(())
    }
    pub(super) fn summary(&self) -> Value {
        json!({"retention_mode":if self.extended{"extended"}else{"default"},"queued_jobs":self.queued,"unprocessed_or_unqueued_jobs":self.omitted,
            "ordinary_files_excluded":self.excluded,"files_truncated_to_prefix":0,
            "empty_files":self.empty,"observations":self.observations,
            "resident_pages_found":self.hits,"nonresident_or_value_entries":self.misses,
            "duplicate_mapping_indices":self.duplicates,"candidate_pages_including_metadata":self.pages.len(),
            "memfd_vma_seeds":self.vma_seeds.len(),"memfd_mappings_walked":self.memfd_mappings.len(),
            "memfd_reverse_mappings":self.reverse_observations,
            "requested_bytes":self.bytes,"read_calls":self.calls,"elapsed_ns":self.elapsed,
            "limits":{"jobs_per_kind":MAX_JOBS,"candidate_pages_including_metadata":MAX_PAGES,
                "xa_nodes_per_file":MAX_XA_NODES_PER_FILE,"additional_discovery_ns":MAX_NS,"additional_read_bytes":MAX_BYTES,
                "maple_walk_nodes_per_mm":MAX_MAPLE_WALK_NODES,"vmas_per_mm":MAX_VMAS_PER_MM,"reverse_vmas_per_mapping":MAX_REVERSE_VMAS},
            "selection":if self.extended{
                "Node-wide resident unlinked regular files (i_nlink == 0, including memfd/O_TMPFILE) and linked tmpfs files (s_magic == 0x01021994, /dev/shm, emptyDir: Memory) via XArray tree walk through open FDs or shared VMAs with address_space.i_mmap reverse validation, plus one backing cache page per discovered executable COW page. Disk-backed linked files remain excluded. Only already resident pages; no file-content reads or fault-in."
            }else{
                "Node-wide resident unlinked regular files (i_nlink == 0, including memfd/O_TMPFILE) via XArray tree walk through open FDs or shared memfd VMAs with address_space.i_mmap reverse validation, plus one backing cache page per discovered executable COW page. Ordinary linked files (i_nlink != 0, including linked tmpfs unless --extended) are excluded. Only already resident pages; no file-content reads or fault-in."
            },
            "meaning":"Cache is current in-memory file content, not a trusted original. References are live and checked around reads; payload bytes can still change."})
    }
}

// A value/shadow/swap/zero entry is not resident file bytes. Retry and other
// internal entries are errors, never silently treated as an absent page.
fn leaf(entry: u64) -> Result<Option<u64>> {
    if entry == 0 || entry & 1 != 0 || entry == (257 << 2 | 2) {
        return Ok(None);
    }
    if entry & 3 != 0 {
        return Err("unsupported or racing XArray leaf".into());
    }
    Ok(Some(entry))
}
fn require_supported_cache_fs(magic: u64) -> Result<()> {
    // Hugetlb has special folio bookkeeping and is not qualified here.
    // Report it explicitly instead of assuming the ordinary-folio path.
    if magic == 0x958458f6 {
        return Err("hugetlbfs cache layout not qualified".into());
    }
    Ok(())
}
fn xa_slot(index: u64, shift: u64, count: usize, root: bool) -> Result<Option<u64>> {
    if shift > 60 || count != 64 {
        return Err("unsupported XArray geometry".into());
    }
    if root && index.checked_shr(shift as u32 + 6).unwrap_or(0) != 0 {
        return Ok(None);
    }
    Ok(Some((index >> shift) & 63))
}
fn xa_sibling(entry: u64, at: u64) -> Result<Option<u64>> {
    if entry & 3 != 2 || entry >> 2 >= 63 {
        return Ok(None);
    }
    let sibling = entry >> 2;
    if sibling >= at {
        return Err("invalid XArray sibling".into());
    }
    Ok(Some(sibling))
}
fn folio_pa(page: u64, base: u64, size: u64, first: u64, count: u64, index: u64) -> Result<u64> {
    if size == 0
        || page < base
        || !(page - base).is_multiple_of(size)
        || count == 0
        || count > 262144
        || !count.is_power_of_two()
        || index < first
        || index - first >= count
    {
        return Err("page cache folio bounds".into());
    }
    ((page - base) / size)
        .checked_add(index - first)
        .and_then(|p| p.checked_mul(PAGE))
        .ok_or_else(|| "cache PFN overflow".into())
}
impl Scan<'_, '_> {
    fn queue_cache(&mut self, kind: JobKind) {
        if self.cache.queued_by_kind[kind.group()] >= MAX_JOBS {
            self.cache.omitted += 1;
            return;
        }
        self.cache.queued_by_kind[kind.group()] += 1;
        self.cache.jobs.push(Job {
            kind,
            identity: self.task_identity.clone(),
            checks: self.task_checks.clone(),
        });
        self.cache.queued += 1;
    }
    pub(super) fn queue_file_cache(&mut self, file: u64, origin: Value) -> Result<()> {
        // Admission is a hint; small_file revalidates the complete chain later.
        let inode = self.value(file, "file", "f_inode")?;
        let links = self.value(inode, "inode", "i_nlink")?;
        if links != 0 && !self.cache.extended {
            self.cache.excluded += 1;
            return Ok(());
        }
        let sb = self.value(inode, "inode", "i_sb")?;
        let magic = self.value(sb, "super_block", "s_magic")?;
        if links != 0 && !(self.cache.extended && magic == TMPFS_MAGIC) {
            self.cache.excluded += 1;
            return Ok(());
        }
        require_supported_cache_fs(magic)?;
        self.queue_cache(JobKind::Fd { file, origin });
        Ok(())
    }
    pub(super) fn queue_memfd_discovery(&mut self, task: u64) -> Result<()> {
        let mm = self.value(task, "task_struct", "mm")?;
        if mm == 0 || self.cache.maps_mms.contains(&mm) {
            return Ok(());
        }
        if self.cache.maps_jobs.len() >= MAX_JOBS {
            self.cache.omitted += 1;
            return Ok(());
        }
        let mut checks = self.task_checks.clone();
        checks.push(self.expect(task, "task_struct", "mm", mm)?);
        self.cache.maps_mms.insert(mm);
        self.cache.maps_jobs.push(Job {
            kind: JobKind::Maps { task, mm },
            identity: self.task_identity.clone(),
            checks,
        });
        Ok(())
    }
    fn scan_mm(&mut self, task: u64, mm: u64) -> Result<()> {
        self.expect(task, "task_struct", "mm", mm)?;
        let vmas = self.collect_mm_vmas(mm)?;
        for vma in vmas {
            if now() >= self.live.deadline
                || self.live.read_bytes.get() >= self.live.read_limit
                || crate::CANCEL.load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err("mm VMA discovery budget exhausted".into());
            }
            let file = self.value(vma, "vm_area_struct", "vm_file")?;
            if file == 0 {
                continue;
            }
            let flags = self.value(vma, "vm_area_struct", "vm_flags")?;
            if flags & 8 != 0 {
                let inode = self.value(file, "file", "f_inode")?;
                if inode == 0 {
                    continue;
                }
                let links = self.value(inode, "inode", "i_nlink")?;
                if links != 0 && !self.cache.extended {
                    continue;
                }
                let mode = self.value(inode, "inode", "i_mode")?;
                if mode & 0xf000 != 0x8000 {
                    continue;
                }
                let sb = self.value(inode, "inode", "i_sb")?;
                if self.value(sb, "super_block", "s_magic")? != TMPFS_MAGIC {
                    continue;
                }
                let start = self.value(vma, "vm_area_struct", "vm_start")?;
                let end = self.value(vma, "vm_area_struct", "vm_end")?;
                let pgoff = self.value(vma, "vm_area_struct", "vm_pgoff")?;
                let ino = self.value(inode, "inode", "i_ino")?;
                if start < end
                    && start % PAGE == 0
                    && end % PAGE == 0
                    && ino != 0
                    && self.cache.vma_seeds.insert((mm, start))
                {
                    self.queue_cache(JobKind::Vma {
                        task,
                        seed: MemfdSeed {
                            start,
                            end,
                            page_offset: pgoff,
                            inode: ino,
                        },
                    });
                }
            } else if flags & 4 != 0 && !self.code_targets.is_empty() {
                let start = self.value(vma, "vm_area_struct", "vm_start")?;
                let end = self.value(vma, "vm_area_struct", "vm_end")?;
                if !self
                    .code_targets
                    .iter()
                    .any(|t| start <= t.va && t.va < end)
                {
                    continue;
                }
                let inode = self.value(file, "file", "f_inode")?;
                if inode == 0 {
                    continue;
                }
                let pgoff = self.value(vma, "vm_area_struct", "vm_pgoff")?;
                let ino = self.value(inode, "inode", "i_ino")?;
                let s_dev = if self.field("super_block", "s_dev").is_ok() {
                    let sb = self.value(inode, "inode", "i_sb")?;
                    if sb != 0 {
                        Some(self.value(sb, "super_block", "s_dev")? as u32)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let mut matched = Vec::new();
                for t in &self.code_targets {
                    if start <= t.va
                        && t.va < end
                        && pgoff
                            .checked_mul(PAGE)
                            .and_then(|o| o.checked_add(t.va - start))
                            == Some(t.file_offset)
                        && (t.inode == 0
                            || (t.inode == ino && t.dev.zip(s_dev).is_none_or(|(a, b)| a == b)))
                        && self
                            .cache
                            .cow_seen
                            .insert((inode, t.file_offset / PAGE, t.physical))
                    {
                        matched.push((t.va, t.file_offset, t.physical));
                    }
                }
                for (va, offset, physical) in matched {
                    self.queue_cache(JobKind::Cow {
                        task,
                        va,
                        offset,
                        physical,
                    });
                }
            }
        }
        Ok(())
    }
    pub(super) fn capture_cache(&mut self) {
        let begin = now();
        let bytes = self.live.read_bytes.get();
        let calls = self.live.calls.get();
        self.live.deadline = begin.saturating_add(MAX_NS);
        self.live.read_limit = bytes.saturating_add(MAX_BYTES);
        // A full FD bucket must not starve mapped-only memfd or COW discovery.
        for job in std::mem::take(&mut self.cache.maps_jobs) {
            self.cache.queued_by_kind[job.kind.group()] += 1;
            self.cache.jobs.push(job);
            self.cache.queued += 1;
        }
        let mut jobs = std::collections::VecDeque::from(std::mem::take(&mut self.cache.jobs));
        let mut next_group = 0;
        while !jobs.is_empty() {
            let at = (0..4)
                .find_map(|step| {
                    let group = (next_group + step) % 4;
                    jobs.iter().position(|job| job.kind.group() == group)
                })
                .unwrap();
            let job = jobs.remove(at).unwrap();
            next_group = (job.kind.group() + 1) % 4;
            if now() >= self.live.deadline
                || self.cache.pages.len() >= MAX_PAGES
                || self.live.read_bytes.get() >= self.live.read_limit
                || crate::CANCEL.load(std::sync::atomic::Ordering::Relaxed)
            {
                self.cache.omitted += jobs.len() + 1;
                break;
            }
            self.task_identity = job.identity;
            self.task_checks = job.checks;
            let mut observation = match &job.kind {
                JobKind::Fd { file, origin } => json!({"kind":"fd","file":file,"fd":origin["fd"]}),
                JobKind::Maps { .. } => json!({"kind":"mm_vma_discovery"}),
                JobKind::Vma { seed, .. } => {
                    json!({"kind":"shared_memfd_vma","virtual_address":seed.start})
                }
                JobKind::Cow { va, offset, .. } => {
                    json!({"kind":"executable_cow_comparison","virtual_address":va,"file_offset":offset})
                }
            };
            observation["process"] = self.task_identity.clone();
            let counts = (
                self.cache.hits,
                self.cache.misses,
                self.cache.duplicates,
                self.cache.excluded,
                self.cache.empty,
            );
            let result = match job.kind {
                JobKind::Fd { file, origin } => self.small_file(file, origin),
                JobKind::Maps { task, mm } => self.scan_mm(task, mm),
                JobKind::Vma { task, seed } => self.memfd_vma(task, &seed),
                JobKind::Cow {
                    task,
                    va,
                    offset,
                    physical,
                } => self.cow_file(task, va, offset, physical),
            };
            observation["resident_pages_found"] = json!(self.cache.hits - counts.0);
            observation["nonresident_or_value_entries"] = json!(self.cache.misses - counts.1);
            observation["duplicate_mapping_indices"] = json!(self.cache.duplicates - counts.2);
            let drift_msg = result.as_ref().err().and_then(|e| {
                let msg = e.to_string();
                super::Resources::is_live_discovery_drift(&msg).then_some(msg)
            });
            observation["outcome"] = json!(if drift_msg.is_some() {
                "live_drift"
            } else if result.is_err() {
                "error"
            } else if self.cache.excluded > counts.3 {
                "ordinary_file_excluded"
            } else if self.cache.empty > counts.4 {
                "empty_file"
            } else {
                "inspected_resident_entries"
            });
            if let Err(e) = result {
                if let Some(msg) = drift_msg {
                    observation["live_drift"] = json!(msg);
                    self.plan.record_drift("file_cache", msg);
                } else {
                    let msg = e.to_string();
                    observation["error"] = json!(msg);
                    self.plan.issue("file_cache", msg);
                }
            }
            self.cache.observations.push(observation);
            jobs.extend(std::mem::take(&mut self.cache.jobs));
        }
        if self.cache.omitted > 0 {
            self.plan.issue("cache_job_limit", self.cache.omitted);
        }
        self.cache.elapsed = now() - begin;
        self.cache.bytes = self.live.read_bytes.get() - bytes;
        self.cache.calls = self.live.calls.get() - calls;
    }
    fn checked_uint(&self, address: u64, n: usize, checks: &mut Vec<Check>) -> Result<u64> {
        let bytes = self.live.read(address, n)?;
        if n == 0 || n > 8 {
            return Err("cache scalar size".into());
        }
        let mut value = [0; 8];
        value[..n].copy_from_slice(&bytes);
        checks.push(Check {
            address,
            bytes,
            mask: None,
        });
        Ok(u64::from_le_bytes(value))
    }
    fn checked_field(
        &self,
        a: u64,
        t: &'static str,
        n: &'static str,
        checks: &mut Vec<Check>,
    ) -> Result<u64> {
        self.checked_field_mask(a, t, n, None, checks)
    }
    fn checked_word_mask(&self, address: u64, mask: u64, checks: &mut Vec<Check>) -> Result<u64> {
        let value = self.checked_uint(address, 8, checks)?;
        // Other FDs in this allocation word do not identify the target file.
        checks.last_mut().unwrap().mask = Some(mask);
        Ok(value)
    }
    fn checked_field_mask(
        &self,
        a: u64,
        t: &'static str,
        n: &'static str,
        mask: Option<u64>,
        checks: &mut Vec<Check>,
    ) -> Result<u64> {
        let mut check = self.check(a, t, n)?;
        if mask.is_some() && check.bytes.len() != 8 {
            return Err("masked cache scalar must be 64-bit".into());
        }
        check.mask = mask;
        let value = self.field(t, n)?.value(&check.bytes)?;
        checks.push(check);
        Ok(value)
    }
    fn small_file(&mut self, file: u64, origin: Value) -> Result<()> {
        let mut checks = self.task_checks.clone();
        let inode = self.checked_field(file, "file", "f_inode", &mut checks)?;
        let mode = self.checked_field(inode, "inode", "i_mode", &mut checks)?;
        if mode & 0xf000 != 0x8000 {
            return Err("cache file type changed".into());
        }
        let links = self.checked_field(inode, "inode", "i_nlink", &mut checks)?;
        if links != 0 && !self.cache.extended {
            self.cache.excluded += 1;
            return Ok(());
        }
        let sb = self.checked_field(inode, "inode", "i_sb", &mut checks)?;
        let magic = self.checked_field(sb, "super_block", "s_magic", &mut checks)?;
        if links != 0 && !(self.cache.extended && magic == TMPFS_MAGIC) {
            self.cache.excluded += 1;
            return Ok(());
        }
        require_supported_cache_fs(magic)?;
        let size = self.checked_field(inode, "inode", "i_size", &mut checks)?;
        if size > i64::MAX as u64 {
            return Err("negative or corrupt file size".into());
        }
        if size == 0 {
            self.cache.empty += 1;
            return Ok(());
        }
        let number = |name: &str| origin[name].as_u64().ok_or("missing cache FD origin");
        let files = number("files")?;
        let table = number("table")?;
        let array = number("array")?;
        let fd = number("fd")?;
        checks.push(self.expect(files, "files_struct", "fdt", table)?);
        checks.push(self.expect(table, "fdtable", "fd", array)?);
        let max = self.checked_field(table, "fdtable", "max_fds", &mut checks)?;
        if fd >= max {
            return Err("cache FD bounds changed".into());
        }
        if self.checked_uint(array + fd * 8, 8, &mut checks)? != file {
            return Err("cache FD changed".into());
        }
        let bitmap = self.checked_field(table, "fdtable", "open_fds", &mut checks)?;
        let bit = 1u64 << (fd % 64);
        if self.checked_word_mask(bitmap + (fd / 64) * 8, bit, &mut checks)? & bit == 0 {
            return Err("cache FD closed".into());
        }
        let mapping = self.checked_field(file, "file", "f_mapping", &mut checks)?;
        if self.checked_field(mapping, "address_space", "host", &mut checks)? != inode {
            return Err("cache mapping inode mismatch".into());
        }
        let reason = if links == 0 {
            if magic == TMPFS_MAGIC {
                "small_shmem"
            } else {
                "small_unlinked_file"
            }
        } else {
            "extended_linked_tmpfs"
        };
        let origin_detail =
            json!({"kind":reason,"fd":fd,"file_size":size,"nlink":links,"truncated":false});
        self.retain_mapping_pages(file, inode, mapping, size, &origin_detail, &checks)
    }
    fn memfd_vma(&mut self, task: u64, seed: &MemfdSeed) -> Result<()> {
        let va = seed.start;
        let mut checks = self.task_checks.clone();
        let mm = self.checked_field(task, "task_struct", "mm", &mut checks)?;
        if mm == 0 {
            return Err("memfd task lost mm".into());
        }
        let vma = self.vma_at(mm, va, &mut checks)?;
        if self.checked_field(vma, "vm_area_struct", "vm_mm", &mut checks)? != mm {
            return Err("memfd VMA mm mismatch".into());
        }
        let start = self.checked_field(vma, "vm_area_struct", "vm_start", &mut checks)?;
        let end = self.checked_field(vma, "vm_area_struct", "vm_end", &mut checks)?;
        let flags = self.checked_field(vma, "vm_area_struct", "vm_flags", &mut checks)?;
        let offset = self.checked_field(vma, "vm_area_struct", "vm_pgoff", &mut checks)?;
        if start != seed.start || end != seed.end || offset != seed.page_offset || flags & 8 == 0 {
            return Err("memfd shared VMA changed".into());
        }
        let file = self.checked_field(vma, "vm_area_struct", "vm_file", &mut checks)?;
        if file == 0 {
            return Err("memfd VMA lost backing file".into());
        }
        let inode = self.checked_field(file, "file", "f_inode", &mut checks)?;
        if self.checked_field(inode, "inode", "i_mode", &mut checks)? & 0xf000 != 0x8000 {
            return Err("memfd backing object is not regular".into());
        }
        let ino = self.checked_field(inode, "inode", "i_ino", &mut checks)?;
        let links = self.checked_field(inode, "inode", "i_nlink", &mut checks)?;
        if ino != seed.inode || (!self.cache.extended && links != 0) {
            return Err("memfd backing inode changed or still linked".into());
        }
        let sb = self.checked_field(inode, "inode", "i_sb", &mut checks)?;
        if self.checked_field(sb, "super_block", "s_magic", &mut checks)? != TMPFS_MAGIC {
            return Err("memfd VMA is not shmem".into());
        }
        let mapping = self.checked_field(file, "file", "f_mapping", &mut checks)?;
        if self.checked_field(mapping, "address_space", "host", &mut checks)? != inode {
            return Err("memfd address_space inode mismatch".into());
        }
        let size = self.checked_field(inode, "inode", "i_size", &mut checks)?;
        if size > i64::MAX as u64 {
            return Err("negative or corrupt file size".into());
        }
        if size == 0 {
            self.cache.empty += 1;
            return Ok(());
        }
        let reverse = self.reverse_memfd_vmas(mapping, vma, &mut checks)?;
        if self.cache.memfd_mappings.insert(mapping) {
            self.cache.reverse_observations.push(json!({
                "mapping":mapping,"inode":inode,"file_size":size,
                "source_vma":vma,"fd_required":false,"vmas":reverse,
                "observation_phase":"discovery",
                "owner_coverage":"indexed process leaders; empty owners means unresolved, not no users",
                "validation":"Selected reverse-tree and owner fields are included in file-cache ledger same_fields checks. Summary alone does not establish stability or communication."
            }));
        }
        let kind_label = if links == 0 {
            "shared_memfd_vma"
        } else {
            "extended_shared_tmpfs_vma"
        };
        let origin_detail = json!({"kind":kind_label,"vma":vma,
            "virtual_address":va,"file_size":size,"nlink":links,"truncated":false,"fd_required":false});
        self.retain_mapping_pages(file, inode, mapping, size, &origin_detail, &checks)
    }
    fn reverse_memfd_vmas(
        &self,
        mapping: u64,
        target: u64,
        checks: &mut Vec<Check>,
    ) -> Result<Vec<Value>> {
        let root =
            self.checked_field(mapping, "address_space", "i_mmap.rb_root.rb_node", checks)?;
        if root == 0 {
            return Err("memfd i_mmap is empty".into());
        }
        let rb_offset = self.off("vm_area_struct", "shared.rb")?;
        let mut stack = vec![root];
        let mut seen = BTreeSet::new();
        let mut observations = Vec::new();
        let mut found = false;
        while let Some(node) = stack.pop() {
            if !seen.insert(node) {
                return Err("memfd i_mmap tree cycle".into());
            }
            if seen.len() > MAX_REVERSE_VMAS {
                return Err("memfd i_mmap traversal bound".into());
            }
            let vma = node
                .checked_sub(rb_offset)
                .ok_or("memfd rb node underflow")?;
            let file = self.checked_field(vma, "vm_area_struct", "vm_file", checks)?;
            if file == 0 || self.checked_field(file, "file", "f_mapping", checks)? != mapping {
                return Err("memfd reverse VMA mapping mismatch".into());
            }
            let mm = self.checked_field(vma, "vm_area_struct", "vm_mm", checks)?;
            let start = self.checked_field(vma, "vm_area_struct", "vm_start", checks)?;
            let end = self.checked_field(vma, "vm_area_struct", "vm_end", checks)?;
            let pgoff = self.checked_field(vma, "vm_area_struct", "vm_pgoff", checks)?;
            let flags = self.checked_field(vma, "vm_area_struct", "vm_flags", checks)?;
            if mm == 0 || start >= end {
                return Err("memfd reverse VMA invalid".into());
            }
            if vma == target {
                found = true;
            }
            let mut owners = Vec::new();
            let mut host_pids = Vec::new();
            if let Some(candidates) = self.mm_owners.get(&mm) {
                for owner in candidates {
                    for check in &owner.checks {
                        if !check.matches(&self.live.read(check.address, check.bytes.len())?) {
                            return Err("memfd reverse process identity changed".into());
                        }
                    }
                    checks.extend(owner.checks.clone());
                    host_pids.push(owner.pid);
                    owners.push(json!({"task":owner.task,"host_pid":owner.pid,
                        "start_time_ns":owner.start_time_ns}));
                }
            }
            let file_start = pgoff
                .checked_mul(PAGE)
                .ok_or("memfd file offset overflow")?;
            let file_end = file_start
                .checked_add(end - start)
                .ok_or("memfd file range overflow")?;
            observations.push(
                json!({"vma":vma,"mm":mm,"host_pids":host_pids,"owners":owners,
                "virtual_start":start,"virtual_end":end,"file_page_offset":pgoff,
                "file_byte_start":file_start,"file_byte_end_exclusive":file_end,
                "shared":flags & 8 != 0}),
            );
            let left = self.checked_field(node, "rb_node", "rb_left", checks)?;
            let right = self.checked_field(node, "rb_node", "rb_right", checks)?;
            if left != 0 {
                stack.push(left);
            }
            if right != 0 {
                stack.push(right);
            }
        }
        if !found {
            return Err("source VMA absent from address_space.i_mmap".into());
        }
        Ok(observations)
    }
    fn cow_file(&mut self, task: u64, va: u64, offset: u64, physical: u64) -> Result<()> {
        let mut checks = self.task_checks.clone();
        let mm = self.checked_field(task, "task_struct", "mm", &mut checks)?;
        if mm == 0 {
            return Err("COW task lost mm".into());
        }
        let vma = self.vma_at(mm, va, &mut checks)?;
        if self.checked_field(vma, "vm_area_struct", "vm_mm", &mut checks)? != mm {
            return Err("COW VMA mm mismatch".into());
        }
        let start = self.checked_field(vma, "vm_area_struct", "vm_start", &mut checks)?;
        let end = self.checked_field(vma, "vm_area_struct", "vm_end", &mut checks)?;
        let flags = self.checked_field(vma, "vm_area_struct", "vm_flags", &mut checks)?;
        let pgoff = self.checked_field(vma, "vm_area_struct", "vm_pgoff", &mut checks)?;
        if va < start
            || va >= end
            || flags & 4 == 0
            || flags & 8 != 0
            || pgoff
                .checked_mul(PAGE)
                .and_then(|o| o.checked_add(va - start))
                != Some(offset)
        {
            return Err("COW VMA changed or offset mismatch".into());
        }
        let file = self.checked_field(vma, "vm_area_struct", "vm_file", &mut checks)?;
        if file == 0 {
            return Err("COW VMA lost file".into());
        }
        let inode = self.checked_field(file, "file", "f_inode", &mut checks)?;
        let mode = self.checked_field(inode, "inode", "i_mode", &mut checks)?;
        if mode & 0xf000 != 0x8000 {
            return Err("COW backing object is not a regular file".into());
        }
        let sb = self.checked_field(inode, "inode", "i_sb", &mut checks)?;
        require_supported_cache_fs(self.checked_field(
            sb,
            "super_block",
            "s_magic",
            &mut checks,
        )?)?;
        let mapping = self.checked_field(file, "file", "f_mapping", &mut checks)?;
        if self.checked_field(mapping, "address_space", "host", &mut checks)? != inode {
            return Err("COW cache inode mismatch".into());
        }
        let size = self.checked_field(inode, "inode", "i_size", &mut checks)?;
        if offset >= size {
            return Err("COW file offset outside size".into());
        }
        self.cache_page(file,inode,mapping,offset/PAGE,(size-offset).min(PAGE),json!({"kind":"executable_cow_comparison","vma":vma,"virtual_address":va,"cow_physical":physical}),checks)
    }
    // A point lookup, not a walk of every mapping in the process.
    fn vma_at(&self, mm: u64, va: u64, checks: &mut Vec<Check>) -> Result<u64> {
        if self.btf.field("mm_struct", "mm_mt.ma_root").is_ok() {
            self.vma_at_maple(mm, va, checks)
        } else {
            self.vma_at_rb(mm, va, checks)
        }
    }
    fn vma_at_rb(&self, mm: u64, va: u64, checks: &mut Vec<Check>) -> Result<u64> {
        let vm_rb_off = self.off("vm_area_struct", "vm_rb")?;
        let mut node = self.checked_field(mm, "mm_struct", "mm_rb.rb_node", checks)?;
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            if node == 0 || !seen.insert(node) {
                return Err("COW VMA absent or RB cycle".into());
            }
            let vma = node.checked_sub(vm_rb_off).ok_or("RB node underflow")?;
            let start = self.checked_field(vma, "vm_area_struct", "vm_start", checks)?;
            let end = self.checked_field(vma, "vm_area_struct", "vm_end", checks)?;
            if start > end {
                return Err("corrupt VMA RB bounds".into());
            }
            if va < start {
                node = self.checked_field(node, "rb_node", "rb_left", checks)?;
            } else if va >= end {
                node = self.checked_field(node, "rb_node", "rb_right", checks)?;
            } else {
                return Ok(vma);
            }
        }
        Err("RB VMA lookup depth".into())
    }
    fn collect_mm_vmas(&self, mm: u64) -> Result<Vec<u64>> {
        if self.btf.field("mm_struct", "mm_mt.ma_root").is_ok() {
            self.collect_mm_vmas_maple(mm)
        } else {
            self.collect_mm_vmas_rb(mm)
        }
    }
    fn collect_mm_vmas_rb(&self, mm: u64) -> Result<Vec<u64>> {
        let vm_rb_off = self.off("vm_area_struct", "vm_rb")?;
        let root = self.value(mm, "mm_struct", "mm_rb.rb_node")?;
        let mut stack = if root != 0 { vec![root] } else { Vec::new() };
        let mut seen = BTreeSet::new();
        let mut vmas = Vec::new();
        while let Some(node) = stack.pop() {
            if !seen.insert(node) {
                return Err("VMA RB cycle".into());
            }
            if vmas.len() >= MAX_VMAS_PER_MM {
                return Err("mm VMA traversal limit".into());
            }
            let vma = node.checked_sub(vm_rb_off).ok_or("RB node underflow")?;
            vmas.push(vma);
            let right = self.value(node, "rb_node", "rb_right")?;
            let left = self.value(node, "rb_node", "rb_left")?;
            if right != 0 {
                stack.push(right);
            }
            if left != 0 {
                stack.push(left);
            }
        }
        Ok(vmas)
    }
    fn maple_uint_opt(
        &self,
        address: u64,
        n: usize,
        checks: Option<&mut Vec<Check>>,
    ) -> Result<u64> {
        match checks {
            Some(c) => self.checked_uint(address, n, c),
            None => self.live.uint(address, n),
        }
    }
    fn maple_field_opt(
        &self,
        address: u64,
        t: &'static str,
        n: &'static str,
        checks: Option<&mut Vec<Check>>,
    ) -> Result<u64> {
        match checks {
            Some(c) => self.checked_field(address, t, n, c),
            None => self.value(address, t, n),
        }
    }
    fn maple_node_meta(
        &self,
        address: u64,
        kind: u64,
        hi: u64,
        mut checks: Option<&mut Vec<Check>>,
    ) -> Result<(u64, u64, usize)> {
        if self.maple_field_opt(address, "maple_node", "parent", checks.as_deref_mut())? & !255
            == address
        {
            return Err("retired Maple node".into());
        }
        let (slots, pivots, count) = match kind {
            0 => {
                let s = self.field("maple_node", "slot")?;
                (s.offset, 0, s.size / 8)
            }
            1 | 2 => {
                let s = self.field("maple_node", "mr64.slot")?;
                let p = self.off("maple_node", "mr64.pivot")?;
                let max = s.size / 8;
                if !(2..=64).contains(&max) {
                    return Err("Maple slots".into());
                }
                let last = self.maple_uint_opt(
                    address + p + (max as u64 - 2) * 8,
                    8,
                    checks.as_deref_mut(),
                )?;
                let count = if last == 0 {
                    self.maple_field_opt(
                        address,
                        "maple_node",
                        "mr64.meta.end",
                        checks.as_deref_mut(),
                    )? as usize
                        + 1
                } else if last == hi {
                    max - 1
                } else {
                    max
                };
                if count > max {
                    return Err("Maple slot bounds".into());
                }
                (s.offset, p, count)
            }
            3 => {
                let s = self.field("maple_node", "ma64.slot")?;
                let count = self.maple_field_opt(address, "maple_node", "ma64.meta.end", checks)?
                    as usize
                    + 1;
                if count > s.size / 8 {
                    return Err("Maple allocation bounds".into());
                }
                (s.offset, self.off("maple_node", "ma64.pivot")?, count)
            }
            _ => return Err("unsupported Maple node".into()),
        };
        if count == 0 || count > 64 {
            return Err("Maple count".into());
        }
        Ok((slots, pivots, count))
    }
    fn collect_mm_vmas_maple(&self, mm: u64) -> Result<Vec<u64>> {
        let root = self.value(mm, "mm_struct", "mm_mt.ma_root")?;
        if root == 0 {
            return Ok(Vec::new());
        }
        let mut stack = vec![(root, root & 2 != 0, 0u64, u64::MAX)];
        let mut seen_nodes = BTreeSet::new();
        let mut seen_vmas = BTreeSet::new();
        let mut vmas = Vec::new();
        while let Some((entry, is_node, mut lo, hi)) = stack.pop() {
            if entry == 0 {
                continue;
            }
            if !is_node {
                if entry >= 4096 && entry & 3 == 0 && seen_vmas.insert(entry) {
                    if vmas.len() >= MAX_VMAS_PER_MM {
                        return Err("mm VMA traversal limit".into());
                    }
                    vmas.push(entry);
                }
                continue;
            }
            if seen_nodes.len() >= MAX_MAPLE_WALK_NODES || !seen_nodes.insert(entry) {
                return Err("Maple VMA traversal limit or cycle".into());
            }
            let address = entry & !255;
            let kind = (entry >> 3) & 15;
            let (slots, pivots, count) = self.maple_node_meta(address, kind, hi, None)?;
            let mut children = Vec::with_capacity(count);
            for i in 0..count {
                let upper = if kind == 0 {
                    hi
                } else if i + 1 < count {
                    self.live.uint(address + pivots + i as u64 * 8, 8)?
                } else {
                    hi
                };
                if upper < lo || upper > hi {
                    return Err("Maple pivot bounds".into());
                }
                let child = self.live.uint(address + slots + i as u64 * 8, 8)?;
                if child != 0 {
                    children.push((child, kind >= 2, lo, upper));
                }
                if kind != 0 {
                    if upper == hi {
                        break;
                    }
                    lo = upper.checked_add(1).ok_or("Maple index overflow")?;
                }
            }
            for item in children.into_iter().rev() {
                stack.push(item);
            }
        }
        Ok(vmas)
    }
    fn vma_at_maple(&self, mm: u64, va: u64, checks: &mut Vec<Check>) -> Result<u64> {
        let mut entry = self.checked_field(mm, "mm_struct", "mm_mt.ma_root", checks)?;
        let mut node = entry & 2 != 0;
        let (mut lo, mut hi) = (0u64, u64::MAX);
        let mut seen = BTreeSet::new();
        for _ in 0..16 {
            if entry == 0 || !seen.insert(entry) {
                return Err("COW VMA absent or Maple cycle".into());
            }
            if !node {
                return Ok(entry);
            }
            let address = entry & !255;
            let kind = (entry >> 3) & 15;
            let (slots, pivots, count) = self.maple_node_meta(address, kind, hi, Some(checks))?;
            let mut found = None;
            for i in 0..count {
                let upper = if kind == 0 {
                    lo
                } else if i + 1 < count {
                    self.checked_uint(address + pivots + i as u64 * 8, 8, checks)?
                } else {
                    hi
                };
                if upper < lo || upper > hi {
                    return Err("Maple pivot bounds".into());
                }
                if lo <= va && va <= upper {
                    found = Some(self.checked_uint(address + slots + i as u64 * 8, 8, checks)?);
                    hi = upper;
                    break;
                }
                lo = upper.checked_add(1).ok_or("Maple index overflow")?;
            }
            entry = found.ok_or("COW VMA outside Maple slots")?;
            node = kind >= 2;
        }
        Err("Maple lookup depth".into())
    }
    fn validate_folio(
        &self,
        entry: u64,
        mapping: u64,
        mut checks: Vec<Check>,
    ) -> Result<Option<ValidatedFolio>> {
        let Some(page) = leaf(entry)? else {
            return Ok(None);
        };
        let owner = self.checked_field(page, "page", "mapping", &mut checks)?;
        if owner != mapping {
            return Err("page cache owner mismatch".into());
        }
        // XArray leaves are folio heads. folio.index survives the rename of
        // page.index to page.__folio_index in newer kernels.
        let first = self.checked_field(page, "folio", "index", &mut checks)?;
        let head = self.btf.enum_value("pageflags", "PG_head")?;
        let uptodate = self.btf.enum_value("pageflags", "PG_uptodate")?;
        if head >= 64 || uptodate >= 64 || head == uptodate {
            return Err("invalid folio identity flags".into());
        }
        // Dirty, writeback, referenced and lock state may change while the
        // same folio still belongs to the same file/index. Do not mistake
        // those changes for a replaced reference. Keep geometry and initialized
        // content state checked, alongside mapping, index, XArray and owner links.
        let mut flag_mask = (1u64 << head) | (1u64 << uptodate);
        if let Ok(poison) = self.btf.enum_value("pageflags", "PG_hwpoison") {
            if poison >= 64 {
                return Err("invalid hardware poison flag".into());
            }
            flag_mask |= 1u64 << poison;
        }
        let flags = self.checked_field_mask(page, "page", "flags", Some(flag_mask), &mut checks)?;
        let count = if flags & (1u64 << head) != 0 {
            let name = if self.field("folio", "_nr_pages").is_ok() {
                "_nr_pages"
            } else {
                "_folio_nr_pages"
            };
            self.checked_field(page, "folio", name, &mut checks)?
        } else {
            1
        };
        Ok(Some(ValidatedFolio {
            page,
            first,
            count,
            flags,
            flag_mask,
            checks,
        }))
    }
    fn emit_folio_metadata(&mut self, checks: &[Check], detail: &Value) -> Result<()> {
        // Retain pages containing the exact provenance fields, deduplicated.
        for check in checks {
            let mut va = check.address / PAGE * PAGE;
            let end = check.address + check.bytes.len() as u64;
            while va < end {
                let p = self.live.physical(va)?;
                if !self.cache.metadata.contains(&p) {
                    let mut d = detail.clone();
                    d["role"] = json!("reference_metadata");
                    d["virtual_address"] = json!(va);
                    self.add(p, PAGE, "file_cache", d, checks.to_vec())?;
                    self.cache.metadata.insert(p);
                }
                va += PAGE;
            }
        }
        Ok(())
    }
    fn emit_folio_range(
        &mut self,
        ctx: &XaWalkCtx<'_>,
        folio: &ValidatedFolio,
        indices: std::ops::Range<u64>,
    ) -> Result<()> {
        let mut sample_detail = None;
        for idx in indices {
            // A large folio can cover many pages without another XArray read.
            // Bound this loop as well as tree traversal, including direct roots.
            if now() >= self.live.deadline
                || self.live.read_bytes.get() >= self.live.read_limit
                || crate::CANCEL.load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err("file cache folio budget exhausted".into());
            }
            if self.cache.seen.contains(&(ctx.mapping, idx)) {
                self.cache.duplicates += 1;
                continue;
            }
            let pa = folio_pa(
                folio.page,
                self.vmemmap,
                self.page_size,
                folio.first,
                folio.count,
                idx,
            )?;
            let n = (ctx.size - idx * PAGE).min(PAGE);
            let detail = json!({"role":"file_bytes","pid":self.task_identity["pid"],"process":self.task_identity,
                "file":ctx.file,"inode":ctx.inode,"mapping":ctx.mapping,"page":folio.page,"file_offset":idx*PAGE,"origin":ctx.origin,
                "page_flags_at_discovery":folio.flags,"page_flag_validation_mask":folio.flag_mask,"folio_pages":folio.count});
            self.add(pa, n, "file_cache", detail.clone(), folio.checks.clone())?;
            // Failed admission must not suppress a later valid observation.
            self.cache.seen.insert((ctx.mapping, idx));
            self.cache.hits += 1;
            if sample_detail.is_none() {
                sample_detail = Some(detail);
            }
        }
        if let Some(detail) = sample_detail {
            self.emit_folio_metadata(&folio.checks, &detail)?;
        }
        Ok(())
    }
    fn handle_xa_leaf(
        &mut self,
        ctx: &XaWalkCtx<'_>,
        entry: u64,
        slot_base: u64,
        checks: Vec<Check>,
    ) -> Result<()> {
        let Some(folio) = self.validate_folio(entry, ctx.mapping, checks)? else {
            self.cache.misses += 1;
            return Ok(());
        };
        if folio.first > slot_base || slot_base - folio.first >= folio.count {
            return Err("page cache folio bounds".into());
        }
        let end = folio.first.saturating_add(folio.count).min(ctx.max_index);
        self.emit_folio_range(ctx, &folio, folio.first..end)
    }
    fn walk_xa_node(
        &mut self,
        ctx: &mut XaWalkCtx<'_>,
        entry: u64,
        prefix_index: u64,
        parent_shift: Option<u64>,
        depth: usize,
        checks: &[Check],
    ) -> Result<()> {
        if now() >= self.live.deadline
            || self.cache.pages.len() >= MAX_PAGES
            || self.live.read_bytes.get() >= self.live.read_limit
            || crate::CANCEL.load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err("file cache XArray budget exhausted".into());
        }
        if depth >= 16 || !ctx.seen_nodes.insert(entry) {
            return Err("XArray lookup depth/cycle".into());
        }
        if ctx.seen_nodes.len() > MAX_XA_NODES_PER_FILE {
            return Err("XArray traversal node limit".into());
        }
        let node = entry - 2;
        let mut node_checks = checks.to_vec();
        let shift = self.checked_field(node, "xa_node", "shift", &mut node_checks)?;
        if shift > 60 || !shift.is_multiple_of(6) || parent_shift.is_some_and(|ps| shift >= ps) {
            return Err("unsupported XArray geometry".into());
        }
        let raw_slots = self.live.read(node + ctx.slots_offset, 64 * 8)?;
        let slot_span = 1u64 << shift;
        for slot_idx in 0..64u64 {
            let Some(slot_base) = slot_idx
                .checked_mul(slot_span)
                .and_then(|v| prefix_index.checked_add(v))
            else {
                break;
            };
            if slot_base >= ctx.max_index {
                break;
            }
            let off = slot_idx as usize * 8;
            let child_bytes = &raw_slots[off..off + 8];
            let child = u64::from_le_bytes(child_bytes.try_into().unwrap());
            if child == 0 {
                continue;
            }
            match xa_sibling(child, slot_idx) {
                Ok(Some(sibling)) => {
                    let p_off = sibling as usize * 8;
                    let primary =
                        u64::from_le_bytes(raw_slots[p_off..p_off + 8].try_into().unwrap());
                    if primary == 0 || (primary & 3 == 2 && primary >> 2 < 63) {
                        self.plan.issue_or_drift(
                            "file_cache_index",
                            format!(
                                "file {:#x}, index {slot_base}: recursive XArray sibling",
                                ctx.file
                            ),
                        );
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    self.plan.issue_or_drift(
                        "file_cache_index",
                        format!("file {:#x}, index {slot_base}: {error}", ctx.file),
                    );
                    continue;
                }
            }
            let mut slot_checks = node_checks.clone();
            slot_checks.push(Check {
                address: node + ctx.slots_offset + off as u64,
                bytes: child_bytes.to_vec(),
                mask: None,
            });
            if shift > 0 && child & 3 == 2 && child > 4096 {
                self.walk_xa_node(ctx, child, slot_base, Some(shift), depth + 1, &slot_checks)?;
            } else if let Err(error) = self.handle_xa_leaf(ctx, child, slot_base, slot_checks) {
                self.plan.issue_or_drift(
                    "file_cache_index",
                    format!("file {:#x}, index {slot_base}: {error}", ctx.file),
                );
            }
        }
        Ok(())
    }
    fn retain_mapping_pages(
        &mut self,
        file: u64,
        inode: u64,
        mapping: u64,
        size: u64,
        origin: &Value,
        base_checks: &[Check],
    ) -> Result<()> {
        let max_index = size.div_ceil(PAGE);
        let mut checks = base_checks.to_vec();
        let entry = self.checked_field(mapping, "address_space", "i_pages.xa_head", &mut checks)?;
        if entry == 0 {
            return Ok(());
        }
        if entry & 3 != 2 || entry <= 4096 {
            let ctx = XaWalkCtx {
                file,
                inode,
                mapping,
                size,
                max_index,
                origin,
                slots_offset: 0,
                seen_nodes: BTreeSet::new(),
            };
            let Some(folio) = self.validate_folio(entry, mapping, checks)? else {
                self.cache.misses += 1;
                return Ok(());
            };
            if folio.first != 0 {
                return Err("page cache root folio index mismatch".into());
            }
            let end = folio.count.min(max_index);
            return self.emit_folio_range(&ctx, &folio, 0..end);
        }
        let slots = self.field("xa_node", "slots")?;
        if slots.size != 64 * 8 {
            return Err("unsupported XArray geometry".into());
        }
        let mut ctx = XaWalkCtx {
            file,
            inode,
            mapping,
            size,
            max_index,
            origin,
            slots_offset: slots.offset,
            seen_nodes: BTreeSet::new(),
        };
        self.walk_xa_node(&mut ctx, entry, 0, None, 0, &checks)
    }
    #[allow(clippy::too_many_arguments)]
    fn cache_page(
        &mut self,
        file: u64,
        inode: u64,
        mapping: u64,
        index: u64,
        n: u64,
        origin: Value,
        mut checks: Vec<Check>,
    ) -> Result<()> {
        if self.cache.seen.contains(&(mapping, index)) {
            self.cache.duplicates += 1;
            return Ok(());
        }
        let mut entry =
            self.checked_field(mapping, "address_space", "i_pages.xa_head", &mut checks)?;
        let mut seen = BTreeSet::new();
        let mut root = true;
        for depth in 0..16 {
            if entry & 3 != 2 || entry <= 4096 {
                break;
            }
            if depth == 15 || !seen.insert(entry) {
                return Err("XArray lookup depth/cycle".into());
            }
            let node = entry - 2;
            let shift = self.checked_field(node, "xa_node", "shift", &mut checks)?;
            let slots = self.field("xa_node", "slots")?;
            let count = slots.size / 8;
            let Some(at) = xa_slot(index, shift, count, root)? else {
                self.cache.misses += 1;
                return Ok(());
            };
            entry = self.checked_uint(node + slots.offset + at * 8, 8, &mut checks)?;
            if let Some(sibling) = xa_sibling(entry, at)? {
                entry = self.checked_uint(node + slots.offset + sibling * 8, 8, &mut checks)?;
                if entry & 3 == 2 && entry >> 2 < 63 {
                    return Err("recursive XArray sibling".into());
                }
            }
            root = false;
        }
        if root && index != 0 {
            self.cache.misses += 1;
            return Ok(());
        }
        let Some(folio) = self.validate_folio(entry, mapping, checks)? else {
            self.cache.misses += 1;
            return Ok(());
        };
        let ctx = XaWalkCtx {
            file,
            inode,
            mapping,
            size: index * PAGE + n,
            max_index: index + 1,
            origin: &origin,
            slots_offset: 0,
            seen_nodes: BTreeSet::new(),
        };
        self.emit_folio_range(&ctx, &folio, index..index + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_reads_large_folio_with_old_and_new_btf_field_names() {
        use super::super::provenance_tests::TestBtf;
        use std::io::Write;
        for newer in [false, true] {
            const BASE: u64 = 0xffff888000000000;
            let mut b = TestBtf::new();
            let u8t = b.int("u8", 1);
            let u32t = b.int("u32", 4);
            let u64t = b.int("u64", 8);
            let ptr = b.record(&[0, 2 << 24, 0]);
            let array = b.record(&[0, 3 << 24, 0, ptr, u32t, 64]);
            let xa = b.structure("xarray", 8, &[("xa_head", ptr, 0)]);
            b.structure("address_space", 8, &[("i_pages", xa, 0)]);
            b.structure("xa_node", 520, &[("shift", u8t, 0), ("slots", array, 8)]);
            b.structure(
                "page",
                64,
                &[
                    ("flags", u64t, 0),
                    ("mapping", ptr, 24),
                    (if newer { "__folio_index" } else { "index" }, u64t, 32),
                ],
            );
            let count_offset = if newer { 120 } else { 104 };
            b.structure(
                "folio",
                128,
                &[
                    ("index", u64t, 32),
                    (
                        if newer {
                            "_nr_pages"
                        } else {
                            "_folio_nr_pages"
                        },
                        u32t,
                        count_offset,
                    ),
                ],
            );
            let en = b.name("pageflags");
            let head = b.name("PG_head");
            let uptodate = b.name("PG_uptodate");
            b.record(&[en, (6 << 24) | 2, 4, head, 3, uptodate, 4]);
            let path = std::env::temp_dir().join(format!(
                "kerneldump_cache_btf_{}_{}",
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
            let mapping = BASE + 0x1000;
            let node = BASE + 0x1800;
            let page = BASE + 0x2200;
            let put = |data: &mut [u8], at: usize, value: u64, n: usize| {
                data[at..at + n].copy_from_slice(&value.to_le_bytes()[..n])
            };
            put(&mut data, 0x1000, node + 2, 8);
            put(&mut data, 0x1800 + 8 + 8 * 8, page, 8);
            put(&mut data, 0x2200, (1 << 3) | (1 << 4), 8);
            put(&mut data, 0x2200 + 24, mapping, 8);
            put(&mut data, 0x2200 + 32, 8, 8);
            put(&mut data, 0x2200 + count_offset as usize, 4, 4);
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
                vmemmap: BASE + 0x2000,
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
            // Resolve the second page of a four-page folio through an XArray
            // sibling, then ensure a changed file index invalidates evidence.
            core.write_all_at(&(8u64 << 2 | 2).to_le_bytes(), 0x1800 + 8 + 9 * 8)
                .unwrap();
            scan.cache_page(
                BASE + 0x300,
                BASE + 0x400,
                mapping,
                9,
                PAGE,
                json!({"kind":"fd"}),
                vec![],
            )
            .unwrap();
            drop(scan);
            let payload = plan
                .evidence
                .iter()
                .find(|e| e.detail["role"] == "file_bytes")
                .unwrap();
            assert_eq!(payload.detail["physical_start"], 9 * PAGE);
            assert_eq!(payload.detail["file_offset"], 9 * PAGE);
            assert_eq!(
                payload.detail["page_flag_validation_mask"],
                (1u64 << 3) | (1u64 << 4)
            );
            // A volatile flag changing does not replace this mapped file folio.
            core.write_all_at(
                &((1u64 << 3) | (1u64 << 4) | (1u64 << 15)).to_le_bytes(),
                0x2200,
            )
            .unwrap();
            plan.witness(0, data.len() as u64, true, |va, buf| {
                virtual_read(&core, &segs, va, buf)
            });
            assert_eq!(plan.finish()["complete"], true);
            core.write_all_at(&12u64.to_le_bytes(), 0x2200 + 32)
                .unwrap();
            let changed = plan.witness(0, data.len() as u64, true, |va, buf| {
                virtual_read(&core, &segs, va, buf)
            });
            assert!(
                changed
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r["same_fields"] == false)
            );
            let finished = plan.finish();
            assert_eq!(finished["complete"], true);
            assert!(finished["live_drift_count"].as_u64().unwrap() > 0);
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn hugetlb_cache_is_not_misread_as_a_normal_large_folio() {
        assert!(require_supported_cache_fs(0x958458f6).is_err());
        assert!(require_supported_cache_fs(0x01021994).is_ok());
        assert!(require_supported_cache_fs(0xef53).is_ok());
    }
    #[test]
    fn swapped_zero_retry_and_pointer_are_distinct() {
        for e in [0, 1, 17, (257 << 2) | 2] {
            assert_eq!(leaf(e).unwrap(), None);
        }
        for e in [(256 << 2) | 2, 2, 6, 4098] {
            assert!(leaf(e).is_err());
        }
        assert_eq!(leaf(0xffff800000001000).unwrap(), Some(0xffff800000001000));
    }
    #[test]
    fn sparse_root_does_not_alias_a_low_index_and_siblings_must_point_back() {
        assert_eq!(xa_slot(65, 0, 64, true).unwrap(), None);
        assert_eq!(xa_slot(65, 6, 64, true).unwrap(), Some(1));
        assert_eq!(xa_slot(65, 0, 64, false).unwrap(), Some(1));
        assert!(xa_slot(0, 61, 64, true).is_err());
        assert!(xa_slot(0, 0, 32, true).is_err());
        assert_eq!(xa_sibling(2, 5).unwrap(), Some(0));
        assert!(xa_sibling((5 << 2) | 2, 5).is_err());
        assert!(xa_sibling((6 << 2) | 2, 5).is_err());
        assert_eq!(xa_sibling((256 << 2) | 2, 5).unwrap(), None);
    }
    #[test]
    fn large_folio_uses_requested_subpage_not_head() {
        assert_eq!(
            folio_pa(0x1000 + 64 * 100, 0x1000, 64, 32, 16, 37).unwrap(),
            105 * PAGE
        );
        for index in [31, 48] {
            assert!(folio_pa(0x1000, 0x1000, 64, 32, 16, index).is_err());
        }
        assert!(folio_pa(0x1001, 0x1000, 64, 0, 1, 0).is_err());
        assert!(folio_pa(0x1000, 0x1000, 64, 0, 3, 0).is_err());
    }
    #[test]
    fn cache_limit_counts_unique_metadata_and_payload_pages() {
        let mut s = CacheState::default();
        s.reserve(&(0..MAX_PAGES as u64).collect::<Vec<_>>())
            .unwrap();
        s.reserve(&[0, 1]).unwrap();
        assert!(s.reserve(&[MAX_PAGES as u64]).is_err());
        assert_eq!(s.pages.len(), MAX_PAGES);
    }
    #[test]
    fn vma_at_falls_back_to_linux_5x_mm_rb_when_maple_tree_absent() {
        use super::super::provenance_tests::TestBtf;
        use std::io::Write;
        const BASE: u64 = 0xffff888000000000;
        let mut b = TestBtf::new();
        let u64t = b.int("u64", 8);
        let ptr = b.record(&[0, 2 << 24, 0]);
        let rb_root = b.structure("rb_root", 8, &[("rb_node", ptr, 0)]);
        let rb_node = b.structure("rb_node", 24, &[("rb_right", ptr, 8), ("rb_left", ptr, 16)]);
        b.structure("mm_struct", 8, &[("mm_rb", rb_root, 0)]);
        b.structure(
            "vm_area_struct",
            40,
            &[
                ("vm_start", u64t, 0),
                ("vm_end", u64t, 8),
                ("vm_rb", rb_node, 16),
            ],
        );
        let path =
            std::env::temp_dir().join(format!("kerneldump_mm_rb_{}_{}", std::process::id(), now()));
        let mut core = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut data = vec![0u8; 4 * PAGE as usize];
        let put = |data: &mut [u8], at: usize, value: u64| {
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        let mm = BASE;
        let vma_root = BASE + 0x200;
        let vma_left = BASE + 0x300;
        let vma_right = BASE + 0x400;
        // mm_rb.rb_node points to &vma_root.vm_rb (+16)
        put(&mut data, 0, vma_root + 16);
        // root VMA [0x4000, 0x6000)
        put(&mut data, 0x200, 0x4000);
        put(&mut data, 0x208, 0x6000);
        put(&mut data, 0x218, vma_right + 16); // rb_right @ 16+8=24
        put(&mut data, 0x220, vma_left + 16); // rb_left @ 16+16=32
        // left VMA [0x1000, 0x3000)
        put(&mut data, 0x300, 0x1000);
        put(&mut data, 0x308, 0x3000);
        // right VMA [0x8000, 0x9000)
        put(&mut data, 0x400, 0x8000);
        put(&mut data, 0x408, 0x9000);
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
            vmemmap: BASE,
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
        let mut checks = Vec::new();
        assert_eq!(scan.vma_at(mm, 0x4500, &mut checks).unwrap(), vma_root);
        assert_eq!(scan.vma_at(mm, 0x1800, &mut checks).unwrap(), vma_left);
        assert_eq!(scan.vma_at(mm, 0x8000, &mut checks).unwrap(), vma_right);
        assert!(scan.vma_at(mm, 0x7000, &mut checks).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
