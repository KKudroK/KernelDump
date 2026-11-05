use crate::{Result, now, sha};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs::{self, File},
    io,
    os::unix::fs::FileExt,
    path::Path,
};

// Count bytes actually returned by source pread calls, including bytes read
// before a later short read/error. These are not output size or disk I/O.
#[derive(Default)]
pub(crate) struct ReadCounter {
    calls: Cell<u64>,
    bytes: Cell<u64>,
    interrupted: Cell<u64>,
    errors: Cell<u64>,
    eof: Cell<u64>,
}
impl ReadCounter {
    pub(crate) fn json(&self) -> Value {
        json!({"calls":self.calls.get(),"returned_bytes":self.bytes.get(),
            "interrupted_calls":self.interrupted.get(),"error_calls":self.errors.get(),"zero_byte_calls":self.eof.get()})
    }
    pub(crate) fn exact_with<F>(
        &self,
        mut data: &mut [u8],
        mut offset: u64,
        mut read: F,
    ) -> io::Result<()>
    where
        F: FnMut(&mut [u8], u64) -> io::Result<usize>,
    {
        offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read offset overflow"))?;
        while !data.is_empty() {
            self.calls.set(self.calls.get() + 1);
            match read(data, offset) {
                Ok(0) => {
                    self.eof.set(self.eof.get() + 1);
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short source read",
                    ));
                }
                Ok(n) => {
                    if n > data.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid read length",
                        ));
                    }
                    self.bytes.set(self.bytes.get() + n as u64);
                    offset += n as u64;
                    data = &mut data[n..];
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    self.interrupted.set(self.interrupted.get() + 1)
                }
                Err(e) => {
                    self.errors.set(self.errors.get() + 1);
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    fn exact(&self, file: &File, data: &mut [u8], offset: u64) -> io::Result<()> {
        self.exact_with(data, offset, |b, at| file.read_at(b, at))
    }
}

pub const PAGE: u64 = 4096;
pub const UNSAFE: u64 = (1 << 19) | (1 << 20) | (1 << 23);
pub const KEEP: u64 = (1 << 7) | (1 << 26);
// Exclude user/data-cache and free-page classifications. SLAB/PGTABLE take
// precedence because the kernel can export ANON-like bits for kernel metadata.
// Unclassified pages remain ambiguous; this is not an ownership guarantee.
pub const EXCLUDE: u64 = (1 << 5)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12)
    | (1 << 13)
    | (1 << 14)
    | (1 << 21)
    | (1 << 22)
    | (1 << 24);

pub(crate) fn gnu_build_ids(notes: &[u8]) -> Result<Vec<String>> {
    let mut at = 0usize;
    let mut ids = Vec::new();
    while at < notes.len() {
        if notes.len() - at < 12 {
            return Err("truncated kernel note header".into());
        }
        let name_len = u32::from_le_bytes(notes[at..at + 4].try_into().unwrap()) as usize;
        let desc_len = u32::from_le_bytes(notes[at + 4..at + 8].try_into().unwrap()) as usize;
        let kind = u32::from_le_bytes(notes[at + 8..at + 12].try_into().unwrap());
        at += 12;
        let name_end = at.checked_add(name_len).ok_or("note length overflow")?;
        let desc_begin = name_end.checked_add(3).ok_or("note alignment overflow")? & !3;
        let desc_end = desc_begin
            .checked_add(desc_len)
            .ok_or("note length overflow")?;
        let next = desc_end.checked_add(3).ok_or("note alignment overflow")? & !3;
        if next > notes.len() {
            return Err("truncated kernel note body".into());
        }
        if &notes[at..name_end] == b"GNU\0" && kind == 3 {
            ids.push(
                notes[desc_begin..desc_end]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            );
        }
        at = next;
    }
    Ok(ids)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    FullRam,
    KernelFocused,
}
impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Self::FullRam => "full-ram",
            Self::KernelFocused => "kernel-focused",
        }
    }
}
pub fn classify(flags: u64, scope: Scope) -> &'static str {
    if flags & UNSAFE != 0 {
        "unsafe_pfn"
    } else if scope == Scope::FullRam || flags & KEEP != 0 || flags & EXCLUDE == 0 {
        "selected"
    } else {
        "policy_excluded"
    }
}

pub fn classify_with_neighbors(flags: &[u64], index: usize, scope: Scope) -> &'static str {
    let status = classify(flags[index], scope);
    // Multi-page kernel structures (such as task_struct = 10,496 bytes in SLUB)
    // span across multiple contiguous physical pages. When an object crosses
    // a SLAB boundary, or when kernel slab allocators place structures adjacent
    // to page cache/unclassified pages, dropping the boundary page causes
    // truncation and breaks Volatility validation (layer.is_valid).
    // Retain immediate boundary neighbors adjacent to any SLAB or PGTABLE page
    // unless the page is explicitly UNSAFE.
    let beside_kernel = index.checked_sub(1).is_some_and(|i| flags[i] & KEEP != 0)
        || flags.get(index + 1).is_some_and(|f| f & KEEP != 0);
    if status == "policy_excluded" && beside_kernel && flags[index] & UNSAFE == 0 {
        "selected"
    } else {
        status
    }
}

pub trait Memory: Send {
    fn resource_pages(&self, _start: u64, _end: u64) -> Vec<u64> {
        Vec::new()
    }
    fn resource_witness(&self, _start: u64, _end: u64, _after: bool) -> Value {
        json!([])
    }
    fn finish_resources(&self) -> Value {
        json!({"complete":true,"applicable":false})
    }
    fn prepare(&mut self, _scope: Scope) {}
    fn code_pages(&self, _start: u64, _end: u64) -> Vec<u64> {
        Vec::new()
    }
    fn code_witness(&self, _start: u64, _end: u64, _after: bool) -> Value {
        json!([])
    }
    fn finish_code_pages(&self) -> Value {
        json!({"complete":true,"applicable":false})
    }
    fn info(&self) -> Value;
    fn io_stats(&self) -> Value {
        json!({"available":false})
    }
    fn ram(&self) -> &[(u64, u64)];
    // Returns a page-aligned physical end and an optional kcore file offset.
    fn chunk(&self, at: u64, end: u64, limit: u64) -> Result<(u64, Option<u64>)>;
    fn flags(&self, at: u64, bytes: u64) -> Result<Vec<u64>>;
    fn read(&self, offset: u64, data: &mut [u8]) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub offset: u64,
    pub va: u64,
    pub pa: u64,
    pub bytes: u64,
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
pub(crate) fn file_offset(base: u64, address: u64, region_start: u64) -> Result<u64> {
    base.checked_add(
        address
            .checked_sub(region_start)
            .ok_or("address precedes mapping")?,
    )
    .ok_or_else(|| "file offset overflow".into())
}

pub fn segments(core: &File) -> Result<Vec<Segment>> {
    segments_counted(core, &ReadCounter::default())
}
fn segments_counted(core: &File, counter: &ReadCounter) -> Result<Vec<Segment>> {
    let mut h = [0u8; 64];
    counter.exact(core, &mut h, 0)?;
    if &h[..7] != b"\x7fELF\x02\x01\x01"
        || u16_at(&h, 16) != 4
        || u16_at(&h, 18) != 62
        || u16_at(&h, 54) != 56
    {
        return Err("requires little-endian x86-64 ELF64 core headers".into());
    }
    let offset = u64_at(&h, 32);
    let count = u16_at(&h, 56) as u64;
    if count == 0
        || count == 65535
        || offset < 64
        || offset
            .checked_add(count * 56)
            .is_none_or(|n| n > 16 * 1024 * 1024)
    {
        return Err("unbounded or invalid kcore program headers".into());
    }
    let mut result = Vec::new();
    for i in 0..count {
        let mut ph = [0u8; 56];
        counter.exact(core, &mut ph, offset + i * 56)?;
        if u32_at(&ph, 0) != 1 {
            continue;
        }
        let s = Segment {
            offset: u64_at(&ph, 8),
            va: u64_at(&ph, 16),
            pa: u64_at(&ph, 24),
            bytes: u64_at(&ph, 32),
        };
        if s.bytes > u64_at(&ph, 40)
            || s.offset.checked_add(s.bytes).is_none()
            || s.va.checked_add(s.bytes).is_none()
        {
            return Err("invalid kcore segment bounds".into());
        }
        result.push(s);
    }
    Ok(result)
}
fn virtual_read(
    core: &File,
    counter: &ReadCounter,
    segments: &[Segment],
    address: u64,
    data: &mut [u8],
) -> Result<()> {
    let end = address
        .checked_add(data.len() as u64)
        .ok_or("virtual address overflow")?;
    let mut hits = segments
        .iter()
        .filter(|s| s.va <= address && end <= s.va + s.bytes);
    let s = hits.next().ok_or("unmapped virtual address")?;
    if hits.next().is_some() {
        return Err("ambiguous virtual address".into());
    }
    counter.exact(core, data, file_offset(s.offset, address, s.va)?)?;
    Ok(())
}
pub fn ram_ranges(text: &str) -> Result<Vec<(u64, u64)>> {
    let mut ranges = Vec::new();
    for line in text.lines() {
        let Some((span, name)) = line.trim().split_once(" : ") else {
            continue;
        };
        if name != "System RAM" {
            continue;
        }
        let (a, b) = span.split_once('-').ok_or("invalid iomem range")?;
        let a = u64::from_str_radix(a, 16)?;
        let b = u64::from_str_radix(b, 16)?;
        let start = a.checked_add(PAGE - 1).ok_or("iomem overflow")? / PAGE * PAGE;
        let end = b.checked_add(1).ok_or("iomem overflow")? / PAGE * PAGE;
        if start < end {
            ranges.push((start, end));
        }
    }
    ranges.sort_unstable();
    if ranges.is_empty() || ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err("physical System RAM addresses unavailable or overlapping".into());
    }
    Ok(ranges)
}

pub struct Source {
    pod: Option<crate::pod_scope::PodScope>,
    code_pages: crate::code_pages::CodePages,
    resources: crate::resources::Resources,
    all_segments: Vec<Segment>,
    extra_selected: std::collections::BTreeSet<u64>,
    core: File,
    flags: File,
    segments: Vec<Segment>,
    ram: Vec<(u64, u64)>,
    info: Value,
    core_probe: ReadCounter,
    core_payload: ReadCounter,
    flags_io: ReadCounter,
}
impl Source {
    pub fn select_pod(&mut self, uid: &str) -> Result<()> {
        let btf = crate::btf::Btf::parse(crate::btf::read_running()?)?;
        // /proc IDs and cgroup paths must be from the host view, not container-relative.
        for (symbol, typ, ns) in [
            ("init_pid_ns", "pid_namespace", "pid"),
            ("init_cgroup_ns", "cgroup_namespace", "cgroup"),
        ] {
            let address = self.info["symbols"][symbol]
                .as_u64()
                .filter(|&v| v != 0)
                .ok_or("host namespace symbol unavailable")?;
            let field = btf.field(typ, "ns.inum")?;
            let mut value = [0u8; 4];
            crate::resources::virtual_read(
                &self.core,
                &self.all_segments,
                address + field.offset,
                &mut value,
            )?;
            let expected = format!("{ns}:[{}]", u32::from_le_bytes(value));
            if fs::read_link(format!("/proc/self/ns/{ns}"))?.to_string_lossy() != expected {
                return Err("--pod requires host PID and cgroup namespace views".into());
            }
        }
        let scope = crate::pod_scope::PodScope::discover(uid, now() + 1_000_000_000)?;
        self.info["pod_scope"] = scope.report.clone();
        self.pod = Some(scope);
        Ok(())
    }
    pub fn add_context(&mut self, request_id: String, clock: Value) {
        self.info["request_id"] = json!(request_id);
        self.info["clock_correlation_start"] = clock;
    }
    pub fn open() -> Result<Self> {
        if !cfg!(all(target_arch = "x86_64", target_endian = "little"))
            || unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != PAGE as i64
        {
            return Err("only little-endian x86-64 hosts with 4KiB pages are supported".into());
        }
        let started = now();
        let core = File::open("/proc/kcore").map_err(|e| {
            format!("/proc/kcore: {e}; requires kernel support and permitted kernel-memory access")
        })?;
        let flags = File::open("/proc/kpageflags").map_err(|e| {
            format!("/proc/kpageflags: {e}; requires page-monitor support and read access")
        })?;
        let core_probe = ReadCounter::default();
        let all = segments_counted(&core, &core_probe)?;
        let mut symbols = serde_json::Map::new();
        for line in fs::read_to_string("/proc/kallsyms")?.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 3
                && [
                    "page_offset_base",
                    "linux_banner",
                    "init_task",
                    "init_pid_ns",
                    "init_cgroup_ns",
                    "_stext",
                    "arch_task_struct_size",
                    "vmemmap_base",
                    "init_top_pgt",
                    "init_level4_pgt",
                    "swapper_pg_dir",
                    "__pgtable_l5_enabled",
                    "pgtable_l5_enabled",
                ]
                .contains(&fields[2])
            {
                symbols.insert(
                    fields[2].to_string(),
                    json!(u64::from_str_radix(fields[0], 16)?),
                );
            }
        }
        let base_address = symbols
            .get("page_offset_base")
            .and_then(Value::as_u64)
            .filter(|&n| n != 0)
            .ok_or("unmasked page_offset_base symbol required; no settings are changed")?;
        let banner_address = symbols
            .get("linux_banner")
            .and_then(Value::as_u64)
            .filter(|&n| n != 0)
            .ok_or("unmasked linux_banner symbol required")?;
        let mut bytes = [0u8; 8];
        virtual_read(&core, &core_probe, &all, base_address, &mut bytes)?;
        let base = u64::from_le_bytes(bytes);
        let mut segments: Vec<_> = all
            .iter()
            .filter(|s| s.bytes != 0 && s.pa != u64::MAX && s.va.checked_sub(s.pa) == Some(base))
            .cloned()
            .collect();
        segments.sort_by_key(|s| s.pa);
        if segments.is_empty()
            || segments.iter().any(|s| s.pa.checked_add(s.bytes).is_none())
            || segments.windows(2).any(|w| w[0].pa + w[0].bytes > w[1].pa)
        {
            return Err("missing/overlapping physical direct map".into());
        }
        let ram = ram_ranges(&fs::read_to_string("/proc/iomem")?)?;
        let mut banner = [0u8; 512];
        virtual_read(&core, &core_probe, &all, banner_address, &mut banner)?;
        let banner =
            String::from_utf8_lossy(banner.split(|&b| b == 0).next().unwrap()).into_owned();
        let notes = fs::read("/sys/kernel/notes")?;
        let runtime_size = match symbols
            .get("arch_task_struct_size")
            .and_then(Value::as_u64)
            .filter(|&n| n != 0)
        {
            Some(address) => {
                let mut data = [0u8; 4];
                match virtual_read(&core, &core_probe, &all, address, &mut data) {
                    Ok(()) => {
                        json!({"bytes":u32::from_le_bytes(data),"symbol_va":address,"observed_ns":now(),"source":"arch_task_struct_size boot-time allocation size; distinct from static BTF sizeof"})
                    }
                    Err(e) => json!({"error":e.to_string(),"symbol_va":address}),
                }
            }
            None => json!({"unavailable":"unmasked arch_task_struct_size symbol not present"}),
        };
        let btf = match fs::read("/sys/kernel/btf/vmlinux") {
            Ok(data) => json!({"sha256":sha(&data),"bytes":data.len()}),
            Err(e) => json!({"unavailable":e.to_string()}),
        };
        let info = json!({"source":"/proc/kcore + /proc/kpageflags + /proc/iomem","kernel_release":fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
            "kernel_banner":banner,"kernel_notes_sha256":sha(&notes),"kernel_gnu_build_ids":gnu_build_ids(&notes)?,"kernel_btf":btf,"runtime_task_struct_allocation":runtime_size,"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            "node":fs::read_to_string("/proc/sys/kernel/hostname")?.trim(),"page_offset_base":base,"symbols":symbols,"ram_ranges":ram,
            "physical_segments":segments.iter().map(|s|json!({"offset":s.offset,"vaddr":s.va,"paddr":s.pa,"filesz":s.bytes})).collect::<Vec<_>>(),
            "meminfo_before":fs::read_to_string("/proc/meminfo")?,"source_init_begin_ns":started,"source_init_end_ns":now()});
        Ok(Self {
            pod: None,
            code_pages: crate::code_pages::CodePages::default(),
            resources: crate::resources::Resources::default(),
            all_segments: all,
            extra_selected: std::collections::BTreeSet::new(),
            core,
            flags,
            segments,
            ram,
            info,
            core_probe,
            core_payload: ReadCounter::default(),
            flags_io: ReadCounter::default(),
        })
    }
}
impl Memory for Source {
    fn prepare(&mut self, _scope: Scope) {
        let start = now();
        let deadline = start + 1_000_000_000;
        self.code_pages =
            crate::code_pages::CodePages::scan(&self.flags, &self.ram, deadline, self.pod.as_ref());
        self.info["code_page_retention"] = self.code_pages.summary();
        self.resources = crate::resources::Resources::discover(
            &self.core,
            &self.all_segments,
            &self.ram,
            &self.info["symbols"],
            crate::btf::read_running(),
            now().saturating_add(1_000_000_000),
            self.pod.as_ref(),
            &self.code_pages.file_targets(),
        );
        let groups = [
            self.code_pages.addresses(0, u64::MAX),
            self.resources.category_pages("network"),
        ];
        let cache = self.resources.category_pages("file_cache");
        self.extra_selected = allocate_with_cache(&groups, &cache, 4096);
        let candidates: std::collections::BTreeSet<_> = groups
            .iter()
            .flatten()
            .chain(cache.iter())
            .copied()
            .collect();
        self.info["resource_retention"] = self.resources.summary();
        self.info["shared_retention_budget"] = json!({"max_candidate_pages":4096,"max_additional_payload_bytes":4096*PAGE,
            "allocation":"round-robin code/network/Pod file cache; deduplicate physical pages",
            "candidate_pages":candidates.len(),"selected_candidate_pages":self.extra_selected.len(),
            "unselected_candidate_pages":candidates.len()-self.extra_selected.len(),"discovery_begin_ns":start,"discovery_end_ns":now(),
            "discovery_limit_ns_per_primary_stage":1_000_000_000,
            "scope":"Code and resource discovery have independent deadlines; Pod file cache has its own recorded budget. Active kernel calls are cooperative"});
    }
    fn code_pages(&self, start: u64, end: u64) -> Vec<u64> {
        self.code_pages
            .addresses(start, end)
            .into_iter()
            .filter(|p| self.extra_selected.contains(p))
            .collect()
    }
    fn code_witness(&self, start: u64, end: u64, after: bool) -> Value {
        self.code_pages.witness(start, end, after)
    }
    fn finish_code_pages(&self) -> Value {
        self.code_pages.finish()
    }
    fn resource_pages(&self, start: u64, end: u64) -> Vec<u64> {
        self.resources
            .addresses(start, end)
            .into_iter()
            .filter(|p| self.extra_selected.contains(p))
            .collect()
    }
    fn resource_witness(&self, start: u64, end: u64, after: bool) -> Value {
        self.resources.witness(start, end, after, |va, data| {
            crate::resources::virtual_read(&self.core, &self.all_segments, va, data)
        })
    }
    fn finish_resources(&self) -> Value {
        let mut result = self.resources.finish();
        if let Some(scope) = &self.pod {
            let validation = scope.finish();
            if validation["complete"] != true {
                result["complete"] = json!(false);
            }
            result["pod_scope_validation"] = validation;
        }
        result
    }
    fn info(&self) -> Value {
        let mut info = self.info.clone();
        info["io_at_probe"] = self.io_stats();
        info
    }
    fn io_stats(&self) -> Value {
        json!({"available":true,"semantics":"Successful acquisition-source pread return bytes, including partial reads before error; not filesystem or physical disk traffic. Code and resource discovery/validation have separate accounting in code_page_retention and resource_retention; BTF/proc metadata are excluded here.",
            "kcore_probe":self.core_probe.json(),"kcore_payload":self.core_payload.json(),"kpageflags":self.flags_io.json(),
            "kcore_total_returned_bytes":self.core_probe.bytes.get()+self.core_payload.bytes.get()})
    }
    fn ram(&self) -> &[(u64, u64)] {
        &self.ram
    }
    fn chunk(&self, at: u64, end: u64, limit: u64) -> Result<(u64, Option<u64>)> {
        let (stop, offset) = if let Some(s) = self
            .segments
            .iter()
            .find(|s| s.pa <= at && at < s.pa + s.bytes)
        {
            (
                end.min(at.saturating_add(limit)).min(s.pa + s.bytes),
                Some(file_offset(s.offset, at, s.pa)?),
            )
        } else {
            (
                end.min(at.saturating_add(limit)).min(
                    self.segments
                        .iter()
                        .filter(|s| s.pa > at)
                        .map(|s| s.pa)
                        .min()
                        .unwrap_or(end),
                ),
                None,
            )
        };
        if stop <= at || !(stop - at).is_multiple_of(PAGE) {
            return Err("unaligned/non-progressing physical map".into());
        }
        Ok((stop, offset))
    }
    fn flags(&self, at: u64, bytes: u64) -> Result<Vec<u64>> {
        let mut data = vec![0u8; (bytes / PAGE * 8) as usize];
        self.flags_io.exact(&self.flags, &mut data, at / PAGE * 8)?;
        Ok(data
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect())
    }
    fn read(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        self.core_payload.exact(&self.core, data, offset)?;
        Ok(())
    }
}

pub(crate) fn allocate_with_cache(
    groups: &[Vec<u64>],
    cache: &[u64],
    limit: usize,
) -> std::collections::BTreeSet<u64> {
    let mut all = groups.to_vec();
    all.push(cache.to_vec());
    allocate_extra(&all, limit)
}
pub(crate) fn allocate_extra(groups: &[Vec<u64>], limit: usize) -> std::collections::BTreeSet<u64> {
    let mut selected = std::collections::BTreeSet::new();
    let mut positions = vec![0usize; groups.len()];
    while selected.len() < limit {
        let mut progressed = false;
        for (i, group) in groups.iter().enumerate() {
            while positions[i] < group.len() {
                let pa = group[positions[i]];
                positions[i] += 1;
                progressed = true;
                if selected.insert(pa) {
                    break;
                }
            }
            if selected.len() == limit {
                break;
            }
        }
        if !progressed {
            break;
        }
    }
    selected
}

pub fn check_readiness(target_dir: Option<&Path>) -> Result<Value> {
    let mut checks = Vec::new();
    let mut ram_bytes = None;
    let layout_check = (|| -> Result<()> {
        let btf = crate::btf::Btf::parse(crate::btf::read_running()?)?;
        for (t, f) in [
            ("task_struct", "start_time"),
            ("files_struct", "fdt"),
            ("file", "private_data"),
            ("fdtable", "open_fds"),
            ("skb_shared_info", "frags"),
            ("sock", "tcp_rtx_queue"),
        ] {
            btf.field(t, f)?;
        }
        Ok(())
    })();
    checks.push(json!({"name":"resource_layout","passed":layout_check.is_ok(),
        "detail":layout_check.err().map(|e|e.to_string()).unwrap_or_else(|| "Running-kernel BTF and required resource layout paths readable".into())}));
    // Use the acquisition source itself: opening kcore alone cannot establish
    // correct ELF/direct-map/symbol/iomem compatibility or usable capabilities.
    match Source::open() {
        Ok(source) => {
            let total = source
                .ram()
                .iter()
                .try_fold(0u64, |n, (a, b)| n.checked_add(b.checked_sub(*a)?));
            ram_bytes = total;
            let sample = (|| -> Result<()> {
                let &(start, end) = source.ram().first().ok_or("no RAM ranges")?;
                source.flags(start, PAGE)?;
                let (_, offset) = source.chunk(start, end, PAGE)?;
                if let Some(offset) = offset {
                    source.read(offset, &mut [0u8; 16])?;
                }
                Ok(())
            })();
            checks.push(json!({"name":"acquisition_source","passed":sample.is_ok() && total.is_some(),
                "detail":sample.err().map(|e|e.to_string()).unwrap_or_else(|| "Acquisition source, required symbols, direct map and sample PFN read validated".into())}));
        }
        Err(e) => {
            checks.push(json!({"name":"acquisition_source","passed":false,"detail":e.to_string()}))
        }
    }
    if let Some(dir) = target_dir {
        match crate::safe_output::probe_storage(dir) {
            Ok(()) => checks.push(json!({"name":"storage_contract","passed":true,
                "detail":"Private directory/file creation, write, file fsync, no-replace publication, directory/parent fsync and probe cleanup passed"})),
            Err(e) => checks.push(json!({"name":"storage_contract","passed":false,"detail":e.to_string()})),
        }
        let required = (ram_bytes.unwrap_or(0) / 10).max(1024 * 1024 * 1024);
        match crate::safe_output::check_available_space(dir,required) {
            Ok(bytes) => checks.push(json!({"name":"storage_capacity","passed":true,"available_bytes":bytes,
                "required_bytes":required,"detail":"Same 10%-of-System-RAM / 1-GiB minimum gate as capture; this does not reserve space"})),
            Err(e) => checks.push(json!({"name":"storage_capacity","passed":false,"required_bytes":required,"detail":e.to_string()})),
        }
    } else {
        checks.push(json!({"name":"storage_contract","passed":false,
            "detail":"Storage not checked: pass --target-dir with an existing output parent directory"}));
    }
    Ok(
        json!({"ready":checks.iter().all(|c|c["passed"]==true),"checks":checks,
        "kernel_release":fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        "effective_uid":unsafe{libc::geteuid()},"target_dir":target_dir,
        "scope":"Readiness at check time only. Capture revalidates; concurrent writes and later policy changes can still fail. No kernel or security settings are changed."}),
    )
}
