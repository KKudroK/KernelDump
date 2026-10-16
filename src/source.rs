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
    let beside_kernel = index
        .checked_sub(1)
        .is_some_and(|i| flags[i] & KEEP != 0)
        || flags.get(index + 1).is_some_and(|f| f & KEEP != 0);
    if status == "policy_excluded" && beside_kernel && flags[index] & UNSAFE == 0 {
        "selected"
    } else {
        status
    }
}

pub trait Memory: Send {
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
        let core = File::open("/proc/kcore")?;
        let flags = File::open("/proc/kpageflags")?;
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
                    "_stext",
                    "arch_task_struct_size",
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
    fn info(&self) -> Value {
        let mut info = self.info.clone();
        info["io_at_probe"] = self.io_stats();
        info
    }
    fn io_stats(&self) -> Value {
        json!({"available":true,"semantics":"Successful pread return bytes, including partial reads before error; not filesystem or physical disk traffic. Metadata files other than kcore/kpageflags are excluded.",
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

pub fn check_readiness(target_dir: Option<&Path>) -> Result<Value> {
    let mut checks = Vec::new();
    let mut overall = true;

    // 1. Root / Privilege check
    let uid = unsafe { libc::geteuid() };
    let is_root = uid == 0;
    checks.push(json!({
        "name": "privilege",
        "passed": is_root,
        "detail": if is_root {
            "Running with administrative privileges (EUID 0)".to_string()
        } else {
            format!("Non-root execution (EUID {uid}); root or CAP_SYS_ADMIN/CAP_SYS_RAWIO required")
        }
    }));
    if !is_root {
        overall = false;
    }

    // 2. /proc/kcore check
    let kcore_ok = File::open("/proc/kcore").is_ok();
    checks.push(json!({
        "name": "proc_kcore",
        "passed": kcore_ok,
        "detail": if kcore_ok {
            "/proc/kcore interface is readable".to_string()
        } else {
            "Cannot access /proc/kcore; ensure root permissions and kernel CONFIG_PROC_KCORE=y".to_string()
        }
    }));
    if !kcore_ok {
        overall = false;
    }

    // 3. /proc/kpageflags check
    let kpageflags_ok = File::open("/proc/kpageflags").is_ok();
    checks.push(json!({
        "name": "proc_kpageflags",
        "passed": kpageflags_ok,
        "detail": if kpageflags_ok {
            "/proc/kpageflags interface is readable".to_string()
        } else {
            "Cannot access /proc/kpageflags; ensure CONFIG_PROC_PAGE_MONITOR=y".to_string()
        }
    }));
    if !kpageflags_ok {
        overall = false;
    }

    // 4. Kernel symbol unmasking (kptr_restrict)
    let mut symbols_unmasked = false;
    let mut sym_detail = String::new();
    if let Ok(kallsyms) = fs::read_to_string("/proc/kallsyms") {
        for line in kallsyms.lines().take(500) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] != "0000000000000000" && parts[0] != "0" {
                symbols_unmasked = true;
                sym_detail = "Kernel symbols unmasked and visible".to_string();
                break;
            }
        }
        if !symbols_unmasked {
            sym_detail = "Kernel symbols are masked (all zeros); /proc/sys/kernel/kptr_restrict must be <= 1 for root".to_string();
        }
    } else {
        sym_detail = "Cannot read /proc/kallsyms".to_string();
    }
    checks.push(json!({
        "name": "kptr_restrict",
        "passed": symbols_unmasked,
        "detail": sym_detail
    }));
    if !symbols_unmasked {
        overall = false;
    }

    // 5. Target directory disk space (if specified)
    if let Some(dir) = target_dir {
        let parent = if dir.exists() {
            dir
        } else {
            dir.parent().unwrap_or(Path::new("."))
        };
        match crate::safe_output::check_available_space(parent, 1024 * 1024 * 1024) {
            Ok(avail) => {
                checks.push(json!({
                    "name": "storage_capacity",
                    "passed": true,
                    "detail": format!("Target filesystem has {} MiB available (>= 1024 MiB reserve)", avail / (1024 * 1024))
                }));
            }
            Err(e) => {
                checks.push(json!({
                    "name": "storage_capacity",
                    "passed": false,
                    "detail": e.to_string()
                }));
                overall = false;
            }
        }
    }

    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    Ok(json!({
        "ready": overall,
        "kernel_release": release,
        "checks": checks
    }))
}
