//! Bounded evidence retention, not an attack detector. No process bytes are
//! read through /proc/PID/mem: payload always comes from the kcore RAM map.
use crate::{CANCEL, now, source::PAGE};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::FileExt,
    sync::atomic::Ordering,
};

const MAX_PROCESSES: usize = 16384;
const MAX_PAGES: usize = 65_536; // Runaway/corrupt-kernel safety ceiling (256 MiB).
const MAX_REFERENCES: usize = 65_536;
const MAX_OPEN_PROCESSES: usize = 4096;
const MAX_EXEC_MAPPINGS: usize = 65536;
const MAX_PROCESS_EXEC_MAPPINGS: usize = 4096;
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCAN_NS: u64 = 5_000_000_000;
const MAX_VALIDATION_NS: u64 = 5_000_000_000;
const MAX_VALIDATION_BYTES: u64 = 64 * 1024 * 1024;
const MAPS_LIMIT: usize = 1024 * 1024;
const PFN_MASK: u64 = (1 << 55) - 1;

fn open_process_limit() -> usize {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0
        && lim.rlim_cur != libc::RLIM_INFINITY
    {
        return MAX_OPEN_PROCESSES.min((lim.rlim_cur as usize).saturating_sub(64).max(64));
    }
    MAX_OPEN_PROCESSES
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CowTarget {
    pub va: u64,
    pub file_offset: u64,
    pub physical: u64,
    pub inode: u64,
    pub dev: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    inode: u64,
    dev: Option<u32>,
    identity: Option<String>,
}
fn mapping(line: &str) -> Option<Mapping> {
    let mut fields = line.split_whitespace();
    let (a, b) = fields.next()?.split_once('-')?;
    let perms = fields.next()?.as_bytes();
    let offset = u64::from_str_radix(fields.next()?, 16).ok()?;
    let device = fields.next()?;
    let inode = fields.next()?.parse::<u64>().ok()?;
    // Include both file COW and fileless/JIT executable anonymous pages.
    // W is irrelevant. This is evidence retention, not attack detection.
    if perms.len() != 4 || perms[2] != b'x' || perms[3] != b'p' {
        return None;
    }
    let start = u64::from_str_radix(a, 16).ok()?;
    let end = u64::from_str_radix(b, 16).ok()?;
    if start >= end || end > (1 << 56) || start % PAGE != 0 || end % PAGE != 0 {
        return None;
    }
    let (maj_s, min_s) = device.split_once(':')?;
    let major = u32::from_str_radix(maj_s, 16).ok()?;
    let minor = u32::from_str_radix(min_s, 16).ok()?;
    let dev = (inode != 0 && major < 4096 && minor < 1_048_576).then_some((major << 20) | minor);
    Some(Mapping {
        start,
        end,
        offset,
        inode,
        dev,
        identity: (inode != 0).then(|| format!("{device}:{inode}")),
    })
}
fn anon_pfn(entry: u64) -> Option<u64> {
    // pagemap: present=63, swapped=62, file/shared-anon=61.
    (entry & (1 << 63) != 0 && entry & ((1 << 62) | (1 << 61)) == 0).then_some(entry & PFN_MASK)
}
fn start_time(text: &str) -> Option<u64> {
    // comm may contain spaces and ')'. Field 22 follows the final ')'.
    text.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
fn bounded_text(path: &str, limit: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("proc text exceeds bound"));
    }
    // Names may contain arbitrary bytes. Only ASCII numeric fields participate
    // in identity/selection; lossy display decoding must not reject those fields.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
struct Process {
    pid: u32,
    start: u64,
    pagemap: File,
    maps: Vec<Mapping>,
    maps_truncated: bool,
}
fn executable_maps_unchanged(after_text: &str, before: &[Mapping], truncated: bool) -> bool {
    let iter = after_text.lines().filter_map(mapping);
    if truncated {
        iter.take(before.len()).eq(before.iter().cloned())
            && after_text.lines().filter_map(mapping).count() >= before.len()
    } else {
        iter.eq(before.iter().cloned())
    }
}
struct Reference {
    process: usize,
    va: u64,
    file_offset: Option<u64>,
    file_inode: u64,
    file_dev: Option<u32>,
    identity: Option<String>,
}
#[derive(Default)]
pub struct CodePages {
    pages: BTreeMap<u64, Vec<Reference>>,
    processes: Vec<Process>,
    summary: Value,
    issues: RefCell<Vec<Value>>,
    issue_count: Cell<u64>,
    drift: RefCell<Vec<Value>>,
    drift_count: Cell<u64>,
    validation_bytes: Cell<u64>,
    visited: RefCell<std::collections::BTreeSet<u64>>,
    released: RefCell<std::collections::BTreeSet<u64>>,
}
impl CodePages {
    pub fn file_targets(&self) -> Vec<CowTarget> {
        self.pages
            .iter()
            .flat_map(|(&pa, refs)| {
                refs.iter().filter_map(move |r| {
                    r.file_offset.map(|offset| CowTarget {
                        va: r.va,
                        file_offset: offset,
                        physical: pa,
                        inode: r.file_inode,
                        dev: r.file_dev,
                    })
                })
            })
            .collect()
    }
    fn issue(&self, reason: &str, detail: Value) {
        self.issue_count.set(self.issue_count.get() + 1);
        let mut issues = self.issues.borrow_mut();
        if issues.len() < 32 {
            issues.push(json!({"reason":reason,"detail":detail}));
        }
    }
    fn record_drift(&self, reason: &str, detail: Value) {
        self.drift_count.set(self.drift_count.get() + 1);
        let mut drift = self.drift.borrow_mut();
        if drift.len() < 32 {
            drift.push(json!({"reason":reason,"detail":detail}));
        }
    }
    pub fn note_skipped(&self, pa: u64, flags: u64) {
        if self.pages.contains_key(&pa)
            && !self.visited.borrow().contains(&pa)
            && self.released.borrow_mut().insert(pa)
        {
            self.record_drift("released_before_read", json!({"physical":pa,"flags":flags}));
        }
    }
    pub fn scan(flags: &File, ram: &[(u64, u64)], deadline: u64) -> Self {
        let mut plan = Self::default();
        let begin = now();
        let deadline = deadline.min(begin + MAX_SCAN_NS);
        let open_limit = open_process_limit();
        let mut bytes = 0u64;
        let mut seen = 0;
        let mut exited = 0;
        let mut no_maps = 0;
        let mut references = 0;
        let mut mapped_pages = 0u64;
        let mut mappings_examined = 0usize;
        let mut stop_scan = false;
        let mut pids = Vec::new();
        match fs::read_dir("/proc") {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(e) => {
                            if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                                if pids.len() == MAX_PROCESSES {
                                    plan.issue("process_limit", json!(MAX_PROCESSES));
                                    break;
                                }
                                pids.push(pid);
                            }
                        }
                        Err(e) => plan.issue("proc_enumeration", json!(e.to_string())),
                    }
                }
            }
            Err(e) => plan.issue("proc_enumeration", json!(e.to_string())),
        }
        pids.sort_unstable();
        'processes: for pid in pids {
            if now() >= deadline
                || CANCEL.load(Ordering::Relaxed)
                || bytes + MAPS_LIMIT as u64 + 8192 > MAX_METADATA_BYTES
            {
                plan.issue("scan_time_or_cancel_limit", json!(pid));
                break;
            }
            seen += 1;
            let proc_path = format!("/proc/{pid}");
            let read = || -> io::Result<Option<(u64, String, File, usize)>> {
                let stat = bounded_text(&format!("{proc_path}/stat"), 8192)?;
                let start =
                    start_time(&stat).ok_or_else(|| io::Error::other("invalid process stat"))?;
                let maps = bounded_text(&format!("{proc_path}/maps"), MAPS_LIMIT)?;
                if maps.is_empty() {
                    return Ok(None);
                }
                Ok(Some((
                    start,
                    maps,
                    File::open(format!("{proc_path}/pagemap"))?,
                    stat.len(),
                )))
            };
            let (start, text, pagemap, stat_bytes) = match read() {
                Ok(Some(v)) => v,
                Ok(None) => {
                    no_maps += 1;
                    continue;
                }
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                    exited += 1;
                    continue;
                }
                Err(e) => {
                    plan.issue("process_read", json!({"pid":pid,"error":e.to_string()}));
                    continue;
                }
            };
            bytes += text.len() as u64 + stat_bytes as u64;
            let map_limit = MAX_PROCESS_EXEC_MAPPINGS.min(MAX_EXEC_MAPPINGS - mappings_examined);
            let mut maps: Vec<_> = text
                .lines()
                .filter_map(mapping)
                .take(map_limit + 1)
                .collect();
            let maps_truncated = maps.len() > map_limit;
            if maps_truncated {
                maps.truncate(map_limit);
                plan.issue("executable_mapping_limit", json!(pid));
                stop_scan = MAX_EXEC_MAPPINGS - mappings_examined <= MAX_PROCESS_EXEC_MAPPINGS;
            }
            mappings_examined += maps.len();
            let process_index = plan.processes.len();
            let mut pending = Vec::new();
            let mut pending_pfns = std::collections::BTreeSet::new();
            'maps: for map in &maps {
                let mut va = map.start;
                while va < map.end {
                    let count = ((map.end - va) / PAGE).min(8192) as usize;
                    if bytes + count as u64 * 8 > MAX_METADATA_BYTES
                        || now() >= deadline
                        || CANCEL.load(Ordering::Relaxed)
                    {
                        plan.issue("scan_budget", json!({"pid":pid,"va":va}));
                        stop_scan = true;
                        break 'maps;
                    }
                    let mut entries = vec![0u8; count * 8];
                    bytes += entries.len() as u64;
                    if let Err(e) = pagemap.read_exact_at(&mut entries, va / PAGE * 8) {
                        if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) {
                            exited += 1;
                            pending.clear();
                            pending_pfns.clear();
                            break 'maps;
                        }
                        plan.issue("pagemap_read", json!({"pid":pid,"error":e.to_string()}));
                        break;
                    }
                    mapped_pages += count as u64;
                    for (i, entry) in entries.as_chunks::<8>().0.iter().enumerate() {
                        if i % 64 == 0
                            && (now() >= deadline
                                || bytes + 512 > MAX_METADATA_BYTES
                                || CANCEL.load(Ordering::Relaxed))
                        {
                            plan.issue("scan_budget", json!(pid));
                            stop_scan = true;
                            break 'maps;
                        }
                        let Some(pfn) = anon_pfn(u64::from_le_bytes(*entry)) else {
                            continue;
                        };
                        if pfn == 0 {
                            plan.issue("pfn_masked_or_zero", json!(pid));
                            break;
                        }
                        let Some(pa) = pfn.checked_mul(PAGE) else {
                            plan.issue("invalid_pfn", json!(pfn));
                            continue;
                        };
                        if !ram.iter().any(|&(a, b)| a <= pa && pa < b) {
                            plan.issue("candidate_outside_ram", json!(pa));
                            continue;
                        }
                        let mut f = [0u8; 8];
                        bytes += 8;
                        match flags.read_exact_at(&mut f, pfn * 8) {
                            Ok(()) if u64::from_le_bytes(f) & (1 << 12) != 0 => (),
                            Ok(()) => {
                                plan.record_drift(
                                    "candidate_flags_changed_during_scan",
                                    json!({"pid":pid,"physical":pa}),
                                );
                                continue;
                            }
                            Err(e) => {
                                plan.issue("candidate_flags_read", json!(e.to_string()));
                                continue;
                            }
                        }
                        // Limits apply before allocating records or keeping descriptors.
                        if references + pending.len() >= MAX_REFERENCES
                            || (!plan.pages.contains_key(&pa)
                                && !pending_pfns.contains(&pa)
                                && plan.pages.len() + pending_pfns.len() >= MAX_PAGES)
                            || process_index >= open_limit
                        {
                            plan.issue("candidate_limit", json!({"pid":pid,"physical":pa}));
                            stop_scan = true;
                            break 'maps;
                        }
                        let address = va + i as u64 * PAGE;
                        if !plan.pages.contains_key(&pa) {
                            pending_pfns.insert(pa);
                        }
                        pending.push((
                            pa,
                            Reference {
                                process: process_index,
                                va: address,
                                file_offset: map
                                    .identity
                                    .as_ref()
                                    .map(|_| map.offset + address - map.start),
                                file_inode: map.inode,
                                file_dev: map.dev,
                                identity: map.identity.clone(),
                            },
                        ));
                    }
                    va += count as u64 * PAGE;
                }
            }
            if !pending.is_empty() {
                references += pending.len();
                plan.processes.push(Process {
                    pid,
                    start,
                    pagemap,
                    maps,
                    maps_truncated,
                });
                for (pa, reference) in pending {
                    plan.pages.entry(pa).or_default().push(reference);
                }
            }
            if stop_scan
                || bytes >= MAX_METADATA_BYTES
                || now() >= deadline
                || references >= MAX_REFERENCES
                || plan.pages.len() >= MAX_PAGES
                || plan.processes.len() >= open_limit
            {
                plan.issue("scan_limit", json!(pid));
                break 'processes;
            }
        }
        plan.summary = json!({"policy":"private_executable_anon_v2","begin_ns":begin,"end_ns":now(),
            "elapsed_ns":now()-begin,"processes_examined":seen,"processes_exited_before_scan":exited,
            "processes_without_user_maps":no_maps,
            "processes_with_candidates":plan.processes.len(),"executable_mappings_examined":mappings_examined,"virtual_pages_examined":mapped_pages,
            "candidate_pages":plan.pages.len(),"candidate_references":references,"candidate_bytes":plan.pages.len() as u64*PAGE,
            "metadata_accounted_bytes":bytes,"accounting":"Successful stat/maps lengths plus requested pagemap and candidate kpageflags bytes; failed text reads bounded per process, not included. Separate from source_io kpageflags.","limits":{"processes":MAX_PROCESSES,"unique_pages":MAX_PAGES,
            "references":MAX_REFERENCES,"retained_process_descriptors":MAX_OPEN_PROCESSES,"metadata_bytes":MAX_METADATA_BYTES,
            "executable_mappings":MAX_EXEC_MAPPINGS,"executable_mappings_per_process":MAX_PROCESS_EXEC_MAPPINGS,
            "scan_ns":MAX_SCAN_NS,"maps_bytes_per_process":MAPS_LIMIT},
            "validation_limits":{"ns":MAX_VALIDATION_NS,"metadata_bytes":MAX_VALIDATION_BYTES},
            "scope":"visible proc node-wide; private executable mappings with or without a file; present anonymous physical pages only",
            "exclusions":"No executable permission history. Temporarily non-executable code, shared shmem code, swapped/nonresident bytes and processes outside visible proc are not covered by this additional rule.",
            "pid_namespace":fs::read_link("/proc/self/ns/pid").ok().map(|p|p.to_string_lossy().into_owned()),
            "not_attack_proof":true});
        plan
    }
    pub fn summary(&self) -> Value {
        self.summary.clone()
    }
    pub fn addresses(&self, start: u64, end: u64) -> Vec<u64> {
        self.pages.range(start..end).map(|(&pa, _)| pa).collect()
    }
    pub fn witness(&self, start: u64, end: u64, after: bool) -> Value {
        let mut values = Vec::new();
        for (&pa, refs) in self.pages.range(start..end) {
            if after {
                self.visited.borrow_mut().insert(pa);
            }
            for r in refs {
                let p = &self.processes[r.process];
                let mut b = [0; 8];
                self.validation_bytes.set(self.validation_bytes.get() + 8);
                let result = p.pagemap.read_exact_at(&mut b, r.va / PAGE * 8);
                let matches = result.is_ok() && anon_pfn(u64::from_le_bytes(b)) == Some(pa / PAGE);
                if let Err(ref e) = result
                    && !matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
                    && e.kind() != io::ErrorKind::UnexpectedEof
                {
                    self.issue(
                        "pagemap_validation_read",
                        json!({"pid":p.pid,"va":r.va,"error":e.to_string()}),
                    );
                } else if !matches {
                    self.record_drift(
                        "mapping_changed_or_unreadable",
                        json!({"pid":p.pid,"va":r.va,"physical":pa,"after_read":after}),
                    );
                }
                values.push(json!({"physical":pa,"pid":p.pid,"start_ticks":p.start,"virtual":r.va,
                    "file_device_inode":r.identity,"file_offset":r.file_offset,"same_pfn":matches,
                    "pagemap_entry":result.is_ok().then_some(u64::from_le_bytes(b)),"observed_ns":now()}));
            }
        }
        json!(values)
    }
    pub fn finish(&self) -> Value {
        let begin = now();
        let mut metadata_bytes = 0;
        for p in &self.processes {
            if now() - begin >= MAX_VALIDATION_NS
                || metadata_bytes + MAPS_LIMIT as u64 + 8192 > MAX_VALIDATION_BYTES
            {
                self.issue("final_validation_budget", json!(p.pid));
                break;
            }
            let path = format!("/proc/{}", p.pid);
            let stat = match bounded_text(&format!("{path}/stat"), 8192) {
                Ok(s) => {
                    metadata_bytes += s.len() as u64;
                    s
                }
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                    self.record_drift("process_exited_during_capture", json!(p.pid));
                    continue;
                }
                Err(e) => {
                    self.issue(
                        "final_validation_read",
                        json!({"pid":p.pid,"error":e.to_string()}),
                    );
                    continue;
                }
            };
            let maps = match bounded_text(&format!("{path}/maps"), MAPS_LIMIT) {
                Ok(s) => {
                    metadata_bytes += s.len() as u64;
                    s
                }
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                    self.record_drift("process_exited_during_capture", json!(p.pid));
                    continue;
                }
                Err(e) => {
                    self.issue(
                        "final_validation_read",
                        json!({"pid":p.pid,"error":e.to_string()}),
                    );
                    continue;
                }
            };
            let unchanged = start_time(&stat) == Some(p.start)
                && executable_maps_unchanged(&maps, &p.maps, p.maps_truncated);
            if !unchanged {
                self.record_drift("process_or_executable_maps_changed", json!(p.pid));
            }
        }
        let read_count = self.visited.borrow().len();
        let released_count = self
            .released
            .borrow()
            .difference(&self.visited.borrow())
            .count();
        let omitted = self.pages.len().saturating_sub(read_count + released_count);
        if omitted != 0 {
            self.issue("candidates_not_read", json!(omitted));
        }
        json!({"complete":self.issue_count.get()==0&&omitted==0,"candidate_pages":self.pages.len(),
            "read_candidate_pages":read_count,"released_before_read_pages":released_count,
            "unread_candidate_pages":omitted,"pagemap_validation_requested_bytes":self.validation_bytes.get(),
            "final_validation_metadata_bytes":metadata_bytes,"final_validation_ns":now()-begin,
            "issue_count":self.issue_count.get(),"issues":*self.issues.borrow(),
            "live_drift_count":self.drift_count.get(),"live_drift":*self.drift.borrow(),
            "consistency":"same PFN around payload read plus process start and executable mappings after capture; non-atomic live target drift is recorded separately from collector errors"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executable_file_and_fileless_are_eligible_but_heap_and_shared_are_not() {
        let line = "00400000-00402000 r-xp 00001000 08:01 9 /test file (deleted)";
        let m = mapping(line).unwrap();
        assert_eq!(m.offset, 4096);
        assert_eq!(m.dev, Some((8 << 20) | 1));
        assert!(
            mapping(&line.replace("08:01 9", "00:00 0"))
                .unwrap()
                .dev
                .is_none()
        );
        assert!(
            mapping(&line.replace("08:01 9", "00:00 0"))
                .unwrap()
                .identity
                .is_none()
        );
        for (from, to) in [("r-xp", "rw-p"), ("r-xp", "r-xs")] {
            assert!(mapping(&line.replace(from, to)).is_none());
        }
        assert!(mapping("fffffffffffff000-0000000000000000 r-xp 0 08:01 9").is_none());
    }
    #[test]
    fn pagemap_distinguishes_cow_file_swap_and_nonresident() {
        assert_eq!(anon_pfn((1 << 63) | 123), Some(123));
        assert_eq!(anon_pfn((1 << 63) | (1 << 61) | 123), None);
        assert_eq!(anon_pfn((1 << 62) | 123), None);
        assert_eq!(anon_pfn(123), None);
    }
    #[test]
    fn process_name_parentheses_do_not_shift_start_time() {
        assert_eq!(
            start_time("12 (name ) spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 0"),
            Some(999)
        );
    }
    #[test]
    fn truncated_executable_maps_validate_retained_prefix_without_false_change_alarm() {
        let maps_text = "\
00400000-00401000 r-xp 00000000 08:01 10 /bin/a\n\
00402000-00403000 r-xp 00001000 08:01 10 /bin/a\n\
00404000-00405000 r-xp 00002000 08:01 10 /bin/a\n";
        let prefix: Vec<_> = maps_text.lines().filter_map(mapping).take(2).collect();
        assert!(!executable_maps_unchanged(maps_text, &prefix, false));
        assert!(executable_maps_unchanged(maps_text, &prefix, true));
        let mutated = maps_text.replace("00402000-00403000", "00409000-0040a000");
        assert!(!executable_maps_unchanged(&mutated, &prefix, true));
    }
}
