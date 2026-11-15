use crate::{
    CANCEL, Result, now, sha,
    source::{EXCLUDE, KEEP, Memory, PAGE, Scope, UNSAFE, classify_with_neighbors},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct AcquireOptions {
    pub max_write_mbps: Option<u64>,
}

pub(crate) fn hash_flags_slice(flags: &[u64]) -> String {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 4096];
    for chunk in flags.chunks(512) {
        for (i, flag) in chunk.iter().enumerate() {
            buf[i * 8..(i + 1) * 8].copy_from_slice(&flag.to_le_bytes());
        }
        hash.update(&buf[..chunk.len() * 8]);
    }
    format!("{:x}", hash.finalize())
}

struct Part {
    meta: Value,
    body: Vec<u8>,
}
type Packet = Vec<Part>;
#[derive(Default)]
struct ReadStats {
    begin: u64,
    end: u64,
    chunks: u64,
    ranges: u64,
    flags_ns: u64,
    select_ns: u64,
    address_ns: u64,
    allocate_ns: u64,
    read_ns: u64,
    hash_ns: u64,
    flags_hash_ns: u64,
    queue_wait_ns: u64,
    payload_bytes: u64,
    source_io: Value,
    code_retention: Value,
    resource_retention: Value,
    error: Option<Value>,
}
impl ReadStats {
    fn json(&self) -> Value {
        json!({"begin_ns":self.begin,"end_ns":self.end,"chunks":self.chunks,"ranges":self.ranges,"flags_read_ns":self.flags_ns,"pfn_select_ns":self.select_ns,
    "address_resolve_ns":self.address_ns,"buffer_allocate_zero_ns":self.allocate_ns,"kcore_read_ns":self.read_ns,"payload_hash_ns":self.hash_ns,"flags_hash_ns":self.flags_hash_ns,"queue_wait_ns":self.queue_wait_ns,"payload_bytes":self.payload_bytes,"source_io":self.source_io,"code_page_retention":self.code_retention,"resource_retention":self.resource_retention})
    }
}
fn cancelled(local: &AtomicBool) -> bool {
    CANCEL.load(Ordering::Relaxed) || local.load(Ordering::Relaxed)
}

fn handoff<T>(tx: &mpsc::SyncSender<T>, packet: T, local: &AtomicBool) -> bool {
    if cancelled(local) {
        return false;
    }
    // Receiver belongs to the writer closure. Every normal, error and unwind
    // exit drops it BEFORE the caller joins the producer, waking a blocked send.
    // Cancellation during a kernel I/O call remains cooperative, as before.
    if tx.send(packet).is_err() {
        local.store(true, Ordering::Relaxed);
        return false;
    }
    true
}

fn produce<S: Memory>(
    source: S,
    scope: Scope,
    chunk: u64,
    tx: mpsc::SyncSender<Packet>,
    recycle_rx: mpsc::Receiver<Vec<u8>>,
    local: Arc<AtomicBool>,
) -> ReadStats {
    let mut free_bufs: Vec<Vec<u8>> = Vec::new();
    let mut stats = ReadStats {
        begin: now(),
        ..Default::default()
    };
    let mut error_at = None;
    let result = (|| -> Result<()> {
        for &(start, end) in source.ram() {
            let mut at = start;
            while at < end && !cancelled(&local) {
                error_at = Some(at);
                let t = now();
                let (stop, offset) = source.chunk(at, end, chunk)?;
                stats.address_ns += now() - t;
                if stop <= at
                    || stop > end
                    || stop - at > chunk
                    || !(stop - at).is_multiple_of(PAGE)
                {
                    return Err("invalid source chunk".into());
                }
                let mut packet = Vec::new();
                if let Some(offset) = offset {
                    let t = now();
                    let context_begin = if at > start { at - PAGE } else { at };
                    let context_end = if stop < end { stop + PAGE } else { stop };
                    let flags_result = source.flags(context_begin, context_end - context_begin);
                    let observed = now();
                    stats.flags_ns += observed - t;
                    let context_flags = flags_result?;
                    if context_flags.len() as u64 != (context_end - context_begin) / PAGE {
                        return Err("short PFN flags".into());
                    }
                    let prefix = ((at - context_begin) / PAGE) as usize;
                    let flags = &context_flags[prefix..prefix + ((stop - at) / PAGE) as usize];
                    let code_pages = source.code_pages(at, stop);
                    let resource_pages = source.resource_pages(at, stop);
                    let select = |i: usize, policy| {
                        let status = classify_with_neighbors(&context_flags, i + prefix, policy);
                        let pa = at + i as u64 * PAGE;
                        if status == "policy_excluded"
                            && ((code_pages.binary_search(&pa).is_ok()
                                && flags[i] & (1 << 12) != 0)
                                || (resource_pages.binary_search(&pa).is_ok()
                                    && flags[i] & (UNSAFE | (1 << 10)) == 0))
                        {
                            "selected"
                        } else {
                            status
                        }
                    };
                    let mut i = 0;
                    while i < flags.len() && !cancelled(&local) {
                        let t = now();
                        let status = select(i, scope);
                        let mut j = i + 1;
                        while j < flags.len() && select(j, scope) == status {
                            j += 1;
                        }
                        let address = at + i as u64 * PAGE;
                        let size = (j - i) * PAGE as usize;
                        stats.select_ns += now() - t;
                        error_at = Some(address);
                        let t = now();
                        let flags_sha = hash_flags_slice(&flags[i..j]);
                        stats.flags_hash_ns += now() - t;
                        let mut meta = json!({"physical_start":address,"bytes":size,"status":status,"flags_observed_ns":observed,"flags_sha256":flags_sha});
                        let t = now();
                        let mut flag_runs = Vec::<(u64, u64)>::new();
                        for &flag in &flags[i..j] {
                            if let Some(last) = flag_runs.last_mut().filter(|last| last.1 == flag) {
                                last.0 += 1;
                            } else {
                                flag_runs.push((1, flag));
                            }
                        }
                        meta["flags_rle_pages_u64"] = json!(flag_runs);
                        meta["neighbor_flags_before"] =
                            json!((i + prefix).checked_sub(1).map(|k| context_flags[k]));
                        meta["neighbor_flags_after"] = json!(context_flags.get(j + prefix));
                        stats.select_ns += now() - t;
                        // Full captures retain the contemporaneous lossy-filter
                        // decisions for byte-identical offline omission controls.
                        if scope == Scope::FullRam && status == "selected" {
                            let t = now();
                            let mut omitted = Vec::<(usize, usize)>::new();
                            let mut k = i;
                            while k < j {
                                if select(k, Scope::KernelFocused) != "policy_excluded" {
                                    k += 1;
                                    continue;
                                }
                                let begin = k;
                                k += 1;
                                while k < j && select(k, Scope::KernelFocused) == "policy_excluded"
                                {
                                    k += 1;
                                }
                                omitted.push((
                                    (begin - i) * PAGE as usize,
                                    (k - begin) * PAGE as usize,
                                ));
                            }
                            meta["focused_policy_exclusions_relative"] = json!(omitted);
                            stats.select_ns += now() - t;
                        }
                        let mut body = Vec::new();
                        if status == "selected" {
                            if resource_pages
                                .iter()
                                .any(|&pa| address <= pa && pa < address + size as u64)
                            {
                                meta["resource_pages_before"] =
                                    source.resource_witness(address, address + size as u64, false);
                            }
                            meta["additional_retained_bytes"] = json!(
                                (i..j)
                                    .filter(|&k| classify_with_neighbors(
                                        &context_flags,
                                        k + prefix,
                                        scope
                                    ) == "policy_excluded")
                                    .count() as u64
                                    * PAGE
                            );
                            if code_pages
                                .iter()
                                .any(|&pa| address <= pa && pa < address + size as u64)
                            {
                                meta["code_pages_before"] =
                                    source.code_witness(address, address + size as u64, false);
                                meta["additional_code_bytes"] = json!(
                                    (i..j)
                                        .filter(|&k| classify_with_neighbors(
                                            &context_flags,
                                            k + prefix,
                                            scope
                                        ) == "policy_excluded"
                                            && code_pages
                                                .binary_search(&(at + k as u64 * PAGE))
                                                .is_ok())
                                        .count() as u64
                                        * PAGE
                                );
                            }
                            let t = now();
                            while let Ok(buf) = recycle_rx.try_recv() {
                                if free_bufs.len() < 32 {
                                    free_bufs.push(buf);
                                }
                            }
                            if let Some(pos) = free_bufs.iter().position(|b| b.capacity() >= size) {
                                body = free_bufs.swap_remove(pos);
                                body.clear();
                                body.resize(size, 0);
                            } else {
                                body = vec![0; size];
                            }
                            stats.allocate_ns += now() - t;
                            let t = now();
                            meta["read_begin_ns"] = json!(t);
                            let read_result = source.read(offset + i as u64 * PAGE, &mut body);
                            let end = now();
                            meta["read_end_ns"] = json!(end);
                            stats.read_ns += end - t;
                            read_result?;
                            if meta.get("code_pages_before").is_some() {
                                meta["code_pages_after"] =
                                    source.code_witness(address, address + size as u64, true);
                            }
                            if meta.get("resource_pages_before").is_some() {
                                meta["resource_pages_after"] =
                                    source.resource_witness(address, address + size as u64, true);
                            }
                            let t = now();
                            meta["sha256"] = json!(sha(&body));
                            stats.hash_ns += now() - t;
                            stats.payload_bytes += size as u64;
                        } else if status == "policy_excluded" {
                            for &pa in &code_pages {
                                if address <= pa && pa < address + size as u64 {
                                    source.note_code_page_skipped(
                                        pa,
                                        flags[((pa - at) / PAGE) as usize],
                                    );
                                }
                            }
                            for &pa in &resource_pages {
                                if address <= pa && pa < address + size as u64 {
                                    source.note_resource_page_skipped(
                                        pa,
                                        flags[((pa - at) / PAGE) as usize],
                                    );
                                }
                            }
                        }
                        packet.push(Part { meta, body });
                        stats.ranges += 1;
                        i = j;
                    }
                } else {
                    packet.push(Part {
                        meta: json!({"physical_start":at,"bytes":stop-at,"status":"unmapped"}),
                        body: Vec::new(),
                    });
                    stats.ranges += 1;
                }
                let t = now();
                handoff(&tx, packet, &local);
                stats.queue_wait_ns += now() - t;
                stats.chunks += 1;
                at = stop;
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        stats.error = Some(
            json!({"stage":"read","error":e.to_string(),"physical_start":error_at,"time_ns":now()}),
        );
    }
    stats.end = now();
    stats.source_io = source.io_stats();
    stats.code_retention = source.finish_code_pages();
    stats.resource_retention = source.finish_resources();
    if stats.code_retention["complete"] == false && stats.error.is_none() {
        stats.error = Some(
            json!({"stage":"code_page_retention","error":"Code-page scan or reference validation incomplete; see read_stages.code_page_retention"}),
        );
    }
    if stats.resource_retention["complete"] == false && stats.error.is_none() {
        stats.error = Some(
            json!({"stage":"resource_retention","error":"Resource discovery, budget allocation or reference validation incomplete; see read_stages.resource_retention"}),
        );
    }
    stats
}

fn new_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
fn write_sparse_lime_body(
    file: &mut File,
    body: &[u8],
    sparse_holes: &mut u64,
    written_bytes: &mut u64,
    rate: &mut crate::rate_limit::RateLimiter,
) -> Result<()> {
    const SPARSE_PAGE: usize = PAGE as usize;
    let mut pos = 0usize;
    while pos < body.len() {
        let end = (pos + SPARSE_PAGE).min(body.len());
        if crate::safe_output::is_all_zero(&body[pos..end]) {
            let mut hole_end = end;
            while hole_end < body.len() {
                let next_end = (hole_end + SPARSE_PAGE).min(body.len());
                if !crate::safe_output::is_all_zero(&body[hole_end..next_end]) {
                    break;
                }
                hole_end = next_end;
            }
            let hole_len = (hole_end - pos) as u64;
            file.seek(SeekFrom::Current(hole_len as i64))?;
            *sparse_holes += hole_len;
            pos = hole_end;
        } else {
            let mut data_end = end;
            while data_end < body.len() {
                let next_end = (data_end + SPARSE_PAGE).min(body.len());
                if crate::safe_output::is_all_zero(&body[data_end..next_end]) {
                    break;
                }
                data_end = next_end;
            }
            file.write_all(&body[pos..data_end])?;
            let chunk_written = (data_end - pos) as u64;
            *written_bytes += chunk_written;
            if !rate.account(chunk_written as usize, || CANCEL.load(Ordering::Relaxed)) {
                return Err("cancelled during rate-limited write".into());
            }
            pos = data_end;
        }
    }
    Ok(())
}

pub fn acquire<S: Memory + 'static>(
    source: S,
    output: &Path,
    scope: Scope,
    chunk: usize,
    depth: usize,
) -> Result<Value> {
    acquire_with_options(
        source,
        output,
        scope,
        chunk,
        depth,
        AcquireOptions::default(),
    )
}

pub fn acquire_with_options<S: Memory + 'static>(
    mut source: S,
    output: &Path,
    scope: Scope,
    chunk: usize,
    depth: usize,
    options: AcquireOptions,
) -> Result<Value> {
    if !(1..=16).contains(&depth)
        || chunk == 0
        || chunk > 16 * 1024 * 1024
        || !chunk.is_multiple_of(PAGE as usize)
    {
        return Err("invalid chunk/queue bounds".into());
    }
    let ram = source.ram().to_vec();
    let expected = ram
        .iter()
        .try_fold(0u64, |sum, (a, b)| sum.checked_add(b.checked_sub(*a)?))
        .ok_or("RAM size overflow")?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let min_required = (expected / 10).max(1024 * 1024 * 1024);
    crate::safe_output::check_available_space(parent, min_required)?;
    let output_guard = crate::safe_output::OutputDir::create(output)?;
    let pinned_output = output_guard.path();
    let output = pinned_output.as_path();
    let started = now();
    source.prepare(scope);
    let info = source.info();
    let retention_mode = info["retention_mode"].as_str().unwrap_or("default");
    let mut m = json!({"schema":2,"tool":"kerneldump","implementation":"rust","version":env!("CARGO_PKG_VERSION"),"scope":scope.name(),"retention_mode":retention_mode,"atomic":false,"strict_kernel_only":false,
        "build_provenance":crate::build_info::current(),
        "status":"in_progress","source":info,"ram_ranges":ram,"expected_ram_bytes":expected,"start_ns":started,
        "wall_start_unix_ns":SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),"timebase":"CLOCK_MONOTONIC ns","chunk_bytes":chunk,"queue_depth":depth,"max_write_mbps":options.max_write_mbps,
        "payload_buffer_bound_bytes":(depth+2)*chunk,"filter":{"policy":"kernel-focused-v9","retention_mode":retention_mode,"unsafe_mask":UNSAFE,"retain_mask":KEEP,"exclude_mask":EXCLUDE,"slab_neighbor_pages_retained":1,"exclusion_basis":"LRU, BUDDY, MMAP, ANON, SWAPCACHE, SWAPBACKED, KSM, THP, HUGETLB and ZERO_PAGE are excluded except retained kernel neighbors and deterministic node-wide executable anonymous, referenced queue and file-cache candidates. Unsafe flags always exclude.","retained":"SLAB, PGTABLE, unclassified pages and immediate SLAB/PGTABLE neighbors; additionally node-wide present anonymous pages of private executable mappings (file COW and fileless/JIT code), socket queue bytes up to the 16MiB safety bound via running-kernel BTF, resident unlinked regular files (i_nlink == 0, including memfd/O_TMPFILE) via XArray tree walk (and linked tmpfs files when --extended is enabled), plus backing cache pages corresponding to discovered executable COW pages. Disk-backed linked files remain excluded. See source.shared_retention_budget, source.resource_retention and ledger references."},"errors":[],
        "limitations":["Non-atomic live acquisition: flags, addresses and payload are observed at different times.","Kernel-focused filtering can omit kernel-relevant information and retain user/residual bytes.",
        "kcore can return internally zero-filled bytes; read success is not proof of physical-byte availability.","Unsafe/unmapped PFNs are explicit omissions and prevent complete status.",
        "Cancellation is cooperative; a kernel I/O syscall can block beyond the request.","Payload budget excludes metadata, allocator overhead and OS page cache.","Matching symbols and successful plugins do not prove complete forensic coverage.",
        "Memory hotplug during acquisition is unmonitored; kcore ELF segments are sampled once at initialization."],
        "durability_contract":"Success exit requires payload, ledger, manifest and output/parent directory fsync; stderr/exit status is authoritative on final publication failure."});
    let reserve_path = output.join("manifest_reserve");
    let partial = output.join("memory.lime.partial");
    let final_path = output.join("memory.lime");
    let mut total = 0u64;
    let mut ledger_payload = 0u64;
    let mut excluded = 0u64;
    let mut unavailable = 0u64;
    let mut ranges = 0u64;
    let mut offset = 0u64;
    let mut processed_end = 0u64;
    let mut writing_address = None;
    let mut digest = Sha256::new();
    let mut ledger_digest = Sha256::new();
    let mut write_ns = 0u64;
    let mut hash_ns = 0u64;
    let mut ledger_ns = 0u64;
    let mut receive_ns = 0u64;
    let mut sparse_hole_bytes = 0u64;
    let mut actual_written_bytes = 0u64;
    let local = Arc::new(AtomicBool::new(false));
    let mut worker = None;
    let mut reserve = None;
    let mut payload_owned = None;
    let mut ledger_owned = None;
    // The receiver and writer files must be owned INSIDE this boundary so an
    // unwind disconnects a blocked sender before the outer reader join. Mutable
    // counters/hashes can be incomplete after a panic; they are only published
    // with failed status, never used to promote a complete image.
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        reserve = Some(new_file(&reserve_path)?);
        let r = reserve.as_ref().unwrap();
        let code = unsafe { libc::posix_fallocate(r.as_raw_fd(), 0, 1024 * 1024) };
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code).into());
        }
        r.sync_all()?;
        let mut file = new_file(&partial)?;
        let mut ledger = new_file(&output.join("ranges.jsonl"))?;
        let _ = crate::safe_output::advise_sequential(&file, 0, 0);
        let _ = crate::safe_output::advise_sequential(&ledger, 0, 0);
        payload_owned = Some(file.try_clone()?);
        ledger_owned = Some(ledger.try_clone()?);
        let (tx, rx) = mpsc::sync_channel(depth);
        let (recycle_tx, recycle_rx) = mpsc::sync_channel::<Vec<u8>>(depth * 4 + 4);
        let stop = local.clone();
        worker = Some(thread::spawn(move || {
            produce(source, scope, chunk as u64, tx, recycle_rx, stop)
        }));
        let is_tty = unsafe { libc::isatty(libc::STDERR_FILENO) } == 1;
        let mut last_progress_bytes = 0u64;
        const FLUSH_WINDOW: u64 = 16 * 1024 * 1024;
        let mut window_start = 0u64;
        let mut prev_window: Option<(u64, u64)> = None;
        let mut rate = crate::rate_limit::RateLimiter::new(options.max_write_mbps);
        while !cancelled(&local) {
            let t = now();
            let packet = rx.recv_timeout(Duration::from_millis(50));
            receive_ns += now() - t;
            let packet = match packet {
                Ok(p) => p,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            for mut part in packet {
                let size = part.meta["bytes"].as_u64().ok_or("missing range length")?;
                writing_address = part.meta["physical_start"].as_u64();
                // Check the final record before writing its payload. Reserve
                // the widest possible timestamps so no later metadata growth
                // can leave bytes without a verifiable ledger record.
                let t = now();
                if part.meta["status"] == "selected" {
                    part.meta["file_offset"] = json!(offset);
                    part.meta["write_begin_ns"] = json!(u64::MAX);
                    part.meta["write_end_ns"] = json!(u64::MAX);
                }
                crate::ledger::check_size(&part.meta)?;
                ledger_ns += now() - t;
                match part.meta["status"].as_str() {
                    Some("selected") => {
                        if part.body.len() as u64 != size || size == 0 {
                            return Err("invalid payload length".into());
                        }
                        let start = part.meta["physical_start"]
                            .as_u64()
                            .ok_or("missing physical address")?;
                        let header = lime_header(start, size)?;
                        part.meta["file_offset"] = json!(offset);
                        let t = now();
                        part.meta["write_begin_ns"] = json!(t);
                        file.write_all(&header)?;
                        actual_written_bytes += 32;
                        write_sparse_lime_body(
                            &mut file,
                            &part.body,
                            &mut sparse_hole_bytes,
                            &mut actual_written_bytes,
                            &mut rate,
                        )?;
                        let end = now();
                        part.meta["write_end_ns"] = json!(end);
                        write_ns += end - t;
                        let t = now();
                        digest.update(header);
                        digest.update(&part.body);
                        hash_ns += now() - t;
                        if !part.body.is_empty() {
                            let _ = recycle_tx.try_send(std::mem::take(&mut part.body));
                        }
                        offset += 32 + size;
                        total += size;
                        if offset - window_start >= FLUSH_WINDOW {
                            let _ = crate::safe_output::sync_file_range_write(
                                &file,
                                window_start as i64,
                                (offset - window_start) as i64,
                            );
                            if let Some((pw_start, pw_len)) = prev_window.take() {
                                let _ = crate::safe_output::advise_dontneed(
                                    &file,
                                    pw_start as i64,
                                    pw_len as i64,
                                );
                            }
                            prev_window = Some((window_start, offset - window_start));
                            window_start = offset;
                        }
                    }
                    Some("policy_excluded" | "unsafe_pfn" | "unmapped") => (),
                    _ => return Err("invalid coverage status".into()),
                }
                let t = now();
                let line = crate::ledger::encode(&part.meta)?;
                ledger.write_all(&line)?;
                ledger_digest.update(&line);
                ledger_ns += now() - t;
                ranges += 1;
                match part.meta["status"].as_str().unwrap() {
                    "selected" => ledger_payload += size,
                    "policy_excluded" => excluded += size,
                    _ => unavailable += size,
                }
                processed_end = writing_address.unwrap() + size;
                if is_tty
                    && (total.saturating_sub(last_progress_bytes) >= 16 * 1024 * 1024
                        || processed_end >= expected)
                {
                    last_progress_bytes = total;
                    let pct = (processed_end as f64 / expected as f64 * 100.0).min(100.0);
                    eprint!(
                        "\r\x1b[2K[kerneldump] PFN scan: {:5.1}% | Selected: {:6.1} MiB | Output: {:6.1} MiB",
                        pct,
                        ledger_payload as f64 / (1024.0 * 1024.0),
                        offset as f64 / (1024.0 * 1024.0)
                    );
                    let _ = std::io::stderr().flush();
                }
            }
        }
        // Wake a producer blocked on a full queue before final fsync or join.
        // On error/unwind Rust also drops this closure-owned receiver first.
        drop(rx);
        file.set_len(offset)?;
        m["write_complete_ns"] = json!(now());
        let t = now();
        file.sync_all()?;
        ledger.sync_all()?;
        if let Err(e) = crate::safe_output::advise_dontneed(&file, 0, offset as i64) {
            eprintln!("[kerneldump] warning: advise_dontneed on payload failed: {e}");
        }
        if let Err(e) = crate::safe_output::advise_dontneed(&ledger, 0, 0) {
            eprintln!("[kerneldump] warning: advise_dontneed on ledger failed: {e}");
        }
        if is_tty {
            eprintln!(
                "\r\x1b[2K[kerneldump] Acquisition synced: {:.1} MiB payload durable on storage",
                offset as f64 / (1024.0 * 1024.0)
            );
        }
        m["payload_sync_ns"] = json!(now() - t);
        m["payload_durable_ns"] = json!(now());
        Ok(())
    }));
    match result {
        Ok(Ok(())) => (),
        Ok(Err(e)) => {
            local.store(true, Ordering::Relaxed);
            m["errors"].as_array_mut().unwrap().push(json!({"stage":"write_or_finalize","error":e.to_string(),"physical_start":writing_address,"time_ns":now()}));
        }
        Err(_) => {
            local.store(true, Ordering::Relaxed);
            m["errors"].as_array_mut().unwrap().push(json!({"stage":"writer_panic","error":"acquisition writer unwound; receiver dropped before reader join","physical_start":writing_address,"time_ns":now()}));
        }
    }
    if let Some(worker) = worker {
        m["reader_join_begin_ns"] = json!(now());
        match worker.join() {
            Ok(stats) => {
                m["reader_join_status"] = json!("joined");
                m["capture_complete_ns"] = json!(stats.end);
                m["read_stages"] = stats.json();
                if let Some(error) = stats.error {
                    m["errors"].as_array_mut().unwrap().push(error);
                }
            }
            Err(_) => {
                m["reader_join_status"] = json!("panicked");
                m["errors"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"stage":"worker","error":"reader panicked"}));
            }
        }
        m["reader_join_complete_ns"] = json!(now());
    }
    if CANCEL.load(Ordering::Relaxed) {
        m["errors"].as_array_mut().unwrap().push(
            json!({"stage":"cancel","error":"interrupted; future or queued ranges may be omitted"}),
        );
    }
    let accounted = ledger_payload + excluded + unavailable;
    if accounted != expected {
        m["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!({"stage":"coverage","error":"RAM not fully accounted for"}));
    }
    m["payload_bytes"] = json!(total);
    m["policy_excluded_bytes"] = json!(excluded);
    m["unavailable_bytes"] = json!(unavailable);
    m["ranges"] = json!(ranges);
    m["accounted_bytes"] = json!(accounted);
    m["unprocessed_bytes"] = json!(expected.saturating_sub(accounted));
    m["file_bytes"] = json!(offset);
    m["unledgered_payload_bytes"] = json!(total - ledger_payload);
    m["unprocessed_ranges"] = json!(
        ram.iter()
            .filter_map(|&(a, b)| {
                let start = a.max(processed_end);
                (start < b)
                    .then(|| json!({"physical_start":start,"bytes":b-start,"status":"unprocessed"}))
            })
            .collect::<Vec<_>>()
    );
    m["actual_file_bytes"] = json!(
        payload_owned
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|s| s.len())
            .unwrap_or(0)
    );
    m["allocated_file_bytes"] = json!(
        payload_owned
            .as_ref()
            .and_then(|f| crate::safe_output::allocated_file_bytes(f).ok())
            .unwrap_or(0)
    );
    m["sparse_zero_hole_bytes"] = json!(sparse_hole_bytes);
    m["actual_written_bytes"] = json!(actual_written_bytes);
    let mut payload_path_valid = false;
    for (path, owned) in [
        (&partial, payload_owned.as_ref()),
        (&output.join("ranges.jsonl"), ledger_owned.as_ref()),
    ] {
        if let Some(file) = owned {
            if let Err(e) = crate::safe_output::check_file(path, file) {
                m["errors"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"stage":"output_identity","error":e.to_string(),"path":path}));
            } else if path == &partial {
                payload_path_valid = true;
            }
        }
    }
    if let Err(e) = output_guard.verify_location() {
        m["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!({"stage":"output_directory","error":e.to_string()}));
    }
    m["clock_correlation_end"] = crate::clock_pair();
    m["lime_sha256"] = json!(format!("{:x}", digest.finalize()));
    m["ranges_sha256"] = json!(format!("{:x}", ledger_digest.finalize()));
    m["write_stages"] = json!({"file_write_ns":write_ns,"file_hash_ns":hash_ns,"ledger_serialize_write_hash_ns":ledger_ns,"queue_receive_wait_ns":receive_ns,"sparse_zero_hole_bytes":sparse_hole_bytes,"actual_written_bytes":actual_written_bytes});
    let complete = m["errors"].as_array().unwrap().is_empty() && unavailable == 0;
    m["status"] = json!(if complete {
        "complete_for_policy"
    } else if local.load(Ordering::Relaxed) {
        "failed"
    } else {
        "partial"
    });
    let mut payload_published = false;
    if complete {
        if let Err(e) = crate::safe_output::publish_file(
            &partial,
            &final_path,
            payload_owned
                .as_ref()
                .ok_or("missing original payload handle")?,
        ) {
            m["status"] = json!("failed");
            m["errors"]
                .as_array_mut()
                .unwrap()
                .push(json!({"stage":"publish","error":e.to_string()}));
        } else {
            payload_published = true;
        }
    }
    if let Some(reserve) = reserve.as_ref()
        && let Err(e) = crate::safe_output::remove_owned(&reserve_path, reserve)
    {
        m["status"] = json!("failed");
        m["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!({"stage":"reserve_cleanup","error":e.to_string(),"path":reserve_path,"time_ns":now()}));
    }
    drop(reserve);
    m["artifact"] = if payload_published {
        json!("memory.lime")
    } else if payload_path_valid {
        json!("memory.lime.partial")
    } else {
        Value::Null
    };
    m["artifact_path_validated"] = json!(payload_path_valid);
    m["end_ns"] = json!(now());
    m["elapsed_s"] = json!((now() - started) as f64 / 1e9);
    let published = (|| -> Result<()> {
        let mut f = new_file(&output.join("manifest.json.partial"))?;
        f.write_all(&serde_json::to_vec_pretty(&m)?)?;
        f.sync_all()?;
        crate::safe_output::publish_file(
            &output.join("manifest.json.partial"),
            &output.join("manifest.json"),
            &f,
        )?;
        output_guard.sync()?;
        Ok(())
    })();
    if let Err(e) = published {
        eprintln!(
            "{}",
            json!({"manifest_write_error":e.to_string(),"emergency_manifest":m})
        );
        return Err(e);
    }
    Ok(m)
}

pub fn lime_header(start: u64, size: u64) -> Result<[u8; 32]> {
    let end = start
        .checked_add(size.checked_sub(1).ok_or("empty LiME range")?)
        .ok_or("physical range overflow")?;
    let mut header = [0u8; 32];
    header[..4].copy_from_slice(&0x4c694d45u32.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    header[8..16].copy_from_slice(&start.to_le_bytes());
    header[16..24].copy_from_slice(&end.to_le_bytes());
    Ok(header)
}

#[cfg(test)]
mod channel_tests {
    use super::*;
    #[test]
    fn full_queue_cancellation_drops_receiver_before_join() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(1).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_reader = stop.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            done_tx.send(handoff(&tx, 2, &stop_reader)).unwrap();
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
        stop.store(true, Ordering::Relaxed);
        drop(rx);
        assert!(!done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        reader.join().unwrap();
    }
    #[test]
    fn consumer_unwind_and_producer_failure_disconnect() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(1).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let stop = AtomicBool::new(false);
            done_tx.send(handoff(&tx, 2, &stop)).unwrap();
        });
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _receiver = rx;
            panic!("synthetic writer failure");
        }));
        assert!(!done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        reader.join().unwrap();
        let (tx, rx) = mpsc::sync_channel::<usize>(1);
        let writer = thread::spawn(move || rx.recv_timeout(Duration::from_secs(1)));
        drop(tx);
        assert_eq!(
            writer.join().unwrap(),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }
    #[test]
    fn cancelled_before_send_publishes_no_packet() {
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(!handoff(&tx, vec![0xaa; 4096], &AtomicBool::new(true)));
        assert!(rx.try_recv().is_err());
    }
}
