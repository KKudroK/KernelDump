//! Pod references only; resident memory only. This stage cannot spend the
//! discovery time or extra-page slots already assigned to code and sockets.
use super::*;

const MAX_JOBS: usize = 128;
const MAX_PAGES: usize = 256;
const MAX_FILE: u64 = 64 * 1024;
const MAX_NS: u64 = 100_000_000;
const MAX_BYTES: u64 = 4 * 1024 * 1024;

struct Job {
    kind: JobKind,
    identity: Value,
    checks: Vec<Check>,
}
enum JobKind {
    Fd {
        file: u64,
        origin: Value,
    },
    Cow {
        task: u64,
        va: u64,
        offset: u64,
        physical: u64,
    },
}
#[derive(Default)]
pub(super) struct CacheState {
    jobs: Vec<Job>,
    pages: BTreeSet<u64>,
    metadata: BTreeSet<u64>,
    seen: BTreeSet<(u64, u64)>,
    queued: usize,
    omitted: usize,
    excluded: usize,
    oversized: usize,
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
    pub(super) fn reserve(&mut self, pages: &[u64]) -> Result<()> {
        if self.pages.len() + pages.iter().filter(|p| !self.pages.contains(p)).count() > MAX_PAGES {
            return Err("Pod cache candidate-page limit".into());
        }
        self.pages.extend(pages);
        Ok(())
    }
    pub(super) fn summary(&self) -> Value {
        json!({"queued_jobs":self.queued,"unprocessed_or_unqueued_jobs":self.omitted,
            "ordinary_files_excluded":self.excluded,"files_over_64kib_excluded":self.oversized,
            "empty_files":self.empty,"observations":self.observations,
            "resident_pages_found":self.hits,"nonresident_or_value_entries":self.misses,
            "duplicate_mapping_indices":self.duplicates,"candidate_pages_including_metadata":self.pages.len(),
            "requested_bytes":self.bytes,"read_calls":self.calls,"elapsed_ns":self.elapsed,
            "limits":{"jobs":MAX_JOBS,"candidate_pages_including_metadata":MAX_PAGES,
                "small_file_bytes":MAX_FILE,"additional_discovery_ns":MAX_NS,"additional_read_bytes":MAX_BYTES},
            "selection":"Pod-only small shmem or unlinked regular files through open FDs; one file-cache page per discovered executable COW page. Lower priority than code/network. Only already resident pages; no file-content reads or fault-in.",
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
        || (page - base) % size != 0
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
        if self.cache.jobs.len() == MAX_JOBS {
            self.cache.omitted += 1;
            return;
        }
        self.cache.jobs.push(Job {
            kind,
            identity: self.task_identity.clone(),
            checks: self.task_checks.clone(),
        });
        self.cache.queued += 1;
    }
    pub(super) fn queue_file_cache(&mut self, file: u64, origin: Value) {
        self.queue_cache(JobKind::Fd { file, origin });
    }
    pub(super) fn queue_code_cache(&mut self, task: u64, pid: u32) {
        let targets: Vec<_> = self
            .code_targets
            .iter()
            .filter(|t| t.0 == pid)
            .copied()
            .collect();
        for (_, va, offset, physical) in targets {
            self.queue_cache(JobKind::Cow {
                task,
                va,
                offset,
                physical,
            });
        }
    }
    pub(super) fn capture_cache(&mut self) {
        if self.pod.is_none() {
            return;
        }
        let begin = now();
        let bytes = self.live.read_bytes.get();
        let calls = self.live.calls.get();
        self.live.deadline = self.live.deadline.min(begin.saturating_add(MAX_NS));
        self.live.read_limit = MAX_READ_BYTES.min(bytes.saturating_add(MAX_BYTES));
        let jobs = std::mem::take(&mut self.cache.jobs);
        let mut remaining = jobs.len();
        for job in jobs {
            if now() >= self.live.deadline
                || self.cache.pages.len() >= MAX_PAGES
                || self.live.read_bytes.get() >= self.live.read_limit
                || crate::CANCEL.load(std::sync::atomic::Ordering::Relaxed)
            {
                self.cache.omitted += remaining;
                break;
            }
            remaining -= 1;
            self.task_identity = job.identity;
            self.task_checks = job.checks;
            let mut observation = match &job.kind {
                JobKind::Fd { file, origin } => json!({"kind":"fd","file":file,"fd":origin["fd"]}),
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
                self.cache.oversized,
                self.cache.empty,
            );
            let result = match job.kind {
                JobKind::Fd { file, origin } => self.small_file(file, origin),
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
            observation["outcome"] = json!(if result.is_err() {
                "error"
            } else if self.cache.excluded > counts.3 {
                "ordinary_file_excluded"
            } else if self.cache.oversized > counts.4 {
                "file_over_64kib_excluded"
            } else if self.cache.empty > counts.5 {
                "empty_file"
            } else {
                "inspected_resident_entries"
            });
            if let Err(e) = result {
                observation["error"] = json!(e.to_string());
                self.plan.issue("pod_file_cache", e);
            }
            self.cache.observations.push(observation);
        }
        if self.cache.omitted > 0 {
            self.plan.issue("pod_cache_job_limit", self.cache.omitted);
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
        checks.push(Check { address, bytes });
        Ok(u64::from_le_bytes(value))
    }
    fn checked_field(
        &self,
        a: u64,
        t: &'static str,
        n: &'static str,
        checks: &mut Vec<Check>,
    ) -> Result<u64> {
        let check = self.check(a, t, n)?;
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
        let sb = self.checked_field(inode, "inode", "i_sb", &mut checks)?;
        let magic = self.checked_field(sb, "super_block", "s_magic", &mut checks)?;
        require_supported_cache_fs(magic)?;
        if links != 0 && magic != 0x01021994 {
            self.cache.excluded += 1;
            return Ok(());
        }
        let size = self.checked_field(inode, "inode", "i_size", &mut checks)?;
        if size > MAX_FILE {
            self.cache.oversized += 1;
            return Ok(());
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
        if self.checked_uint(bitmap + (fd / 64) * 8, 8, &mut checks)? & (1 << (fd % 64)) == 0 {
            return Err("cache FD closed".into());
        }
        let mapping = self.checked_field(file, "file", "f_mapping", &mut checks)?;
        if self.checked_field(mapping, "address_space", "host", &mut checks)? != inode {
            return Err("cache mapping inode mismatch".into());
        }
        for index in 0..size.div_ceil(PAGE) {
            let reason = if magic == 0x01021994 {
                "small_shmem"
            } else {
                "small_unlinked_file"
            };
            self.cache_page(
                file,
                inode,
                mapping,
                index,
                (size - index * PAGE).min(PAGE),
                json!({"kind":reason,"fd":fd,"file_size":size}),
                checks.clone(),
            )?;
        }
        Ok(())
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
            if self.checked_field(address, "maple_node", "parent", checks)? & !255 == address {
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
                    if max < 2 || max > 64 {
                        return Err("Maple slots".into());
                    }
                    let last = self.checked_uint(address + p + (max as u64 - 2) * 8, 8, checks)?;
                    let count = if last == 0 {
                        self.checked_field(address, "maple_node", "mr64.meta.end", checks)? as usize
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
                    let count =
                        self.checked_field(address, "maple_node", "ma64.meta.end", checks)?
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
        let Some(page) = leaf(entry)? else {
            self.cache.misses += 1;
            return Ok(());
        };
        if root && index != 0 {
            self.cache.misses += 1;
            return Ok(());
        }
        let owner = self.checked_field(page, "page", "mapping", &mut checks)?;
        if owner != mapping {
            return Err("page cache owner mismatch".into());
        }
        let first = self.checked_field(page, "page", "index", &mut checks)?;
        let flags = self.checked_field(page, "page", "flags", &mut checks)?;
        let head = self.btf.enum_value("pageflags", "PG_head")?;
        if head >= 64 {
            return Err("invalid head flag".into());
        }
        let count = if flags & (1u64 << head) != 0 {
            self.checked_field(page, "folio", "_folio_nr_pages", &mut checks)?
        } else {
            1
        };
        let pa = folio_pa(page, self.vmemmap, self.page_size, first, count, index)?;
        let detail = json!({"role":"file_bytes","pid":self.task_identity["pid"],"process":self.task_identity,
            "file":file,"inode":inode,"mapping":mapping,"page":page,"file_offset":index*PAGE,"origin":origin});
        self.add(pa, n, "file_cache", detail.clone(), checks.clone())?;
        self.cache.seen.insert((mapping, index));
        self.cache.hits += 1;
        // Retain pages containing the exact provenance fields, deduplicated.
        for check in &checks {
            let mut va = check.address / PAGE * PAGE;
            let end = check.address + check.bytes.len() as u64;
            while va < end {
                let p = self.live.physical(va)?;
                if !self.cache.metadata.contains(&p) {
                    let mut d = detail.clone();
                    d["role"] = json!("reference_metadata");
                    d["virtual_address"] = json!(va);
                    self.add(p, PAGE, "file_cache", d, checks.clone())?;
                    self.cache.metadata.insert(p);
                }
                va += PAGE;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
