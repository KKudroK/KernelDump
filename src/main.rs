mod btf;
mod build_info;
mod capture;
mod code_pages;
mod ledger;
mod pod_scope;
mod rate_limit;
mod resources;
mod safe_output;
mod source;
#[cfg(test)]
mod tests;
mod verify;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
static CANCEL: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: i32) {
    CANCEL.store(true, Ordering::Relaxed);
}
fn now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn clock_pair() -> Value {
    let before = now();
    let utc = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    json!({"monotonic_before_ns":before,"wall_unix_utc_ns":utc,"monotonic_after_ns":now()})
}
pub(crate) fn parse_verify_args(args: &[String]) -> Result<PathBuf> {
    match args {
        [cmd, path] if cmd == "verify" && !path.is_empty() && !path.starts_with('-') => {
            Ok(PathBuf::from(path))
        }
        [cmd, flag, path]
            if cmd == "verify"
                && flag == "--output"
                && !path.is_empty()
                && !path.starts_with("--") =>
        {
            Ok(PathBuf::from(path))
        }
        [cmd, flag]
            if cmd == "verify"
                && flag.starts_with("--output=")
                && flag.len() > 9
                && !flag[9..].starts_with("--") =>
        {
            Ok(PathBuf::from(&flag[9..]))
        }
        _ => Err("Usage: kerneldump verify --output EXISTING_DIR".into()),
    }
}
fn run() -> Result<bool> {
    use source::Memory;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--version" {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(true);
    }
    if args.len() == 1 && args[0] == "--build-info" {
        println!("{}", build_info::current());
        return Ok(true);
    }
    if args.is_empty() || args.iter().any(|s| s == "--help") {
        #[cfg(not(feature = "development-options"))]
        {
            println!(
                "kerneldump {}\nUsage:\n  kerneldump --output NEW_DIR [--pod FULL_POD_UID] [--allow-exited-pod] [--request-id ID] [--max-write-mbps 1..10000]\n\nSingle unified workflow: Preflight (storage/BTF/kcore/kpageflags) -> PFN-Selective Sparse LiME Capture -> Header/Ledger Verification.\n  kerneldump verify --output EXISTING_DIR performs full SHA-256 verification.\nLegacy check, capture, probe, and verify DIR commands remain accepted.\n--pod restricts additional executable/code and socket/cache retention to one local Pod UID; base kernel filter stays node-wide.\n--allow-exited-pod permits node-wide kernel acquisition even if no live Pod processes remain.\n--max-write-mbps caps payload write bandwidth in MB/s (1000000 B/s per unit) to protect production disk I/O.\n--version and --build-info report the version and actual executable SHA-256.\nStandalone Rust live physical LiME acquisition for Linux x86-64/4KiB (sparse 4KiB zero-seek, 4MiB chunk pipeline).\nExit 0 confirms complete acquisition for the recorded policy, durable publication, and inline verification; exit 2 means incomplete.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(true);
        }
        #[cfg(feature = "development-options")]
        {
            println!(
                "kerneldump {}\nUsage:\n  kerneldump --output NEW_DIR [--pod FULL_POD_UID] [--allow-exited-pod] [--request-id ID]\n             [--max-write-mbps 1..10000] [--scope full-ram|kernel-focused]\n             [--chunk-mib 1..16] [--queue-depth 1..16]\n\nSingle unified workflow: Preflight -> PFN-Selective Sparse LiME Capture -> Header/Ledger Verification.\n  kerneldump verify --output EXISTING_DIR performs full SHA-256 verification.\nLegacy check, capture, probe, and verify DIR commands remain accepted.\nDefaults: kernel-focused, chunk 4 MiB, queue 2. Requires readable kcore/kpageflags/BTF and\nunmasked page_offset_base/linux_banner; no security settings are changed.\nExit 0 confirms successful policy acquisition, durability, and verification; 2 means incomplete.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(true);
        }
    }
    match args.first().map(String::as_str) {
        Some("check") => {
            let mut target_dir = None;
            let mut json_mode = false;
            let mut index = 1;
            while index < args.len() {
                let arg = &args[index];
                if arg == "--json" && !json_mode {
                    json_mode = true;
                } else if arg == "--target-dir" && target_dir.is_none() {
                    index += 1;
                    let value = args
                        .get(index)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or("--target-dir requires a value")?;
                    target_dir = Some(PathBuf::from(value));
                } else if let Some(value) = arg.strip_prefix("--target-dir=") {
                    if target_dir.is_some() || value.is_empty() {
                        return Err("duplicate or empty --target-dir".into());
                    }
                    target_dir = Some(PathBuf::from(value));
                } else {
                    return Err(format!("unknown/duplicate check option: {arg}").into());
                }
                index += 1;
            }
            let report = source::check_readiness(target_dir.as_deref())?;
            let ready = report["ready"].as_bool().unwrap_or(false);
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "kerneldump system readiness check (Linux {}):",
                    report["kernel_release"]
                );
                if let Some(checks) = report["checks"].as_array() {
                    for c in checks {
                        let passed = c["passed"].as_bool().unwrap_or(false);
                        let symbol = if passed {
                            "[\x1b[32mPASS\x1b[0m]"
                        } else {
                            "[\x1b[31mFAIL\x1b[0m]"
                        };
                        println!(
                            "  {} {:<18} : {}",
                            symbol,
                            c["name"].as_str().unwrap_or(""),
                            c["detail"].as_str().unwrap_or("")
                        );
                    }
                }
                println!();
                if ready {
                    println!("\x1b[32mStatus: READY for live kernel memory acquisition.\x1b[0m");
                } else {
                    println!(
                        "\x1b[31mStatus: NOT READY. Please address failed checks above.\x1b[0m"
                    );
                }
            }
            return Ok(ready);
        }
        Some("probe") => {
            if args.len() != 1 {
                return Err("probe takes no options".into());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&source::Source::open()?.info())?
            );
            return Ok(true);
        }
        Some("verify") => {
            let output = parse_verify_args(&args)?;
            let result = verify::verify(&output)?;
            println!("{result}");
            return Ok(result["status"] == "complete_for_policy");
        }
        Some("capture") => {
            args.remove(0);
        }
        _ => {}
    }
    let mut output: Option<PathBuf> = None;
    let mut pod: Option<String> = None;
    let mut allow_exited_pod = false;
    let mut scope = source::Scope::KernelFocused;
    let mut chunk = 4usize;
    let mut depth = 2usize;
    let mut max_write_mbps: Option<u64> = None;
    let mut request_id = format!("{}-{}", std::process::id(), now());
    let mut seen_req = false;
    let mut seen_scope = false;
    let mut seen_chunk = false;
    let mut seen_depth = false;
    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        let (key, inline_val) = if let Some((k, v)) = arg.split_once('=') {
            (k, Some(v))
        } else {
            (arg.as_str(), None)
        };
        if key == "--allow-exited-pod" {
            if inline_val.is_some() {
                return Err("--allow-exited-pod takes no value".into());
            }
            if allow_exited_pod {
                return Err("duplicate --allow-exited-pod".into());
            }
            allow_exited_pod = true;
            i += 1;
            continue;
        }
        let next_val = |idx: &mut usize, inline: Option<&str>| -> Result<String> {
            if let Some(v) = inline {
                if v.is_empty() {
                    return Err(format!("empty value for {key}").into());
                }
                *idx += 1;
                Ok(v.to_string())
            } else {
                *idx += 2;
                let v = args
                    .get(*idx - 1)
                    .filter(|s| !s.starts_with("--"))
                    .ok_or_else(|| format!("missing value for {key}"))?;
                Ok(v.clone())
            }
        };
        match key {
            "--output" => {
                if output.is_some() {
                    return Err("duplicate --output".into());
                }
                output = Some(PathBuf::from(next_val(&mut i, inline_val)?));
            }
            "--pod" => {
                if pod.is_some() {
                    return Err("duplicate --pod".into());
                }
                pod = Some(pod_scope::uid(&next_val(&mut i, inline_val)?)?);
            }
            "--request-id" => {
                if seen_req {
                    return Err("duplicate --request-id".into());
                }
                seen_req = true;
                request_id = next_val(&mut i, inline_val)?;
            }
            "--max-write-mbps" => {
                if max_write_mbps.is_some() {
                    return Err("duplicate --max-write-mbps".into());
                }
                let v: u64 = next_val(&mut i, inline_val)?.parse()?;
                if !(1..=10_000).contains(&v) {
                    return Err("max-write-mbps must be 1..10000".into());
                }
                max_write_mbps = Some(v);
            }
            "--scope" if cfg!(feature = "development-options") => {
                if seen_scope {
                    return Err("duplicate --scope".into());
                }
                seen_scope = true;
                scope = match next_val(&mut i, inline_val)?.as_str() {
                    "full-ram" => source::Scope::FullRam,
                    "kernel-focused" => source::Scope::KernelFocused,
                    _ => return Err("invalid scope".into()),
                };
            }
            "--chunk-mib" if cfg!(feature = "development-options") => {
                if seen_chunk {
                    return Err("duplicate --chunk-mib".into());
                }
                seen_chunk = true;
                chunk = next_val(&mut i, inline_val)?.parse()?;
            }
            "--queue-depth" if cfg!(feature = "development-options") => {
                if seen_depth {
                    return Err("duplicate --queue-depth".into());
                }
                seen_depth = true;
                depth = next_val(&mut i, inline_val)?.parse()?;
            }
            _ => return Err(format!("unknown option: {key}; use --help").into()),
        }
    }
    if allow_exited_pod && pod.is_none() {
        return Err("--allow-exited-pod requires --pod".into());
    }
    if !(1..=16).contains(&chunk) || !(1..=16).contains(&depth) {
        return Err("chunk-mib and queue-depth must be 1..16".into());
    }
    if request_id.is_empty()
        || request_id.len() > 128
        || !request_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c))
    {
        return Err("invalid request-id".into());
    }
    let output = output.ok_or("--output is required")?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Unified Step 1: Preflight storage contract and required kernel BTF/kcore sources.
    safe_output::probe_storage(parent)?;
    {
        let btf = btf::Btf::parse(btf::read_running()?)?;
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
    }
    let mut memory = source::Source::open()?;
    if let Some(&(start, end)) = memory.ram().first() {
        memory.flags(start, source::PAGE)?;
        let (_, off) = memory.chunk(start, end, source::PAGE)?;
        if let Some(off) = off {
            memory.read(off, &mut [0u8; 16])?;
        }
    }
    if let Some(uid) = pod {
        memory.select_pod_with_policy(&uid, allow_exited_pod)?;
    }
    memory.add_context(request_id, clock_pair());
    // Unified Step 2: Acquire PFN-selective sparse LiME payload + ledger + manifest.
    let m = capture::acquire_with_options(
        memory,
        &output,
        scope,
        chunk * 1024 * 1024,
        depth,
        capture::AcquireOptions { max_write_mbps },
    )?;
    // Unified Step 3: Inline verification (headers, ledger hashes, counters, logical size).
    let verified = if m["status"] == "complete_for_policy" {
        Some(verify::verify_fast(&output)?)
    } else {
        None
    };
    println!(
        "{}",
        json!({
            "status": m["status"],
            "payload_bytes": m["payload_bytes"],
            "file_bytes": m["file_bytes"],
            "allocated_file_bytes": m["allocated_file_bytes"],
            "sparse_zero_hole_bytes": m["sparse_zero_hole_bytes"],
            "policy_excluded_bytes": m["policy_excluded_bytes"],
            "unavailable_bytes": m["unavailable_bytes"],
            "unprocessed_bytes": m["unprocessed_bytes"],
            "elapsed_s": m["elapsed_s"],
            "errors": m["errors"],
            "verified": verified.as_ref().map(|v| &v["verified"]),
            "verification_mode": verified.as_ref().map(|v| &v["mode"]),
            "payload_hash_verified": false,
            "manifest": output.join("manifest.json")
        })
    );
    Ok(m["status"] == "complete_for_policy")
}
fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = interrupted as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}
fn main() {
    install_signal_handlers();
    match run() {
        Ok(true) => (),
        Ok(false) => std::process::exit(2),
        Err(e) => {
            eprintln!("kerneldump: {e}");
            std::process::exit(1)
        }
    }
}
