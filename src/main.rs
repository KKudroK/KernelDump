mod btf;
mod build_info;
mod capture;
mod code_pages;
mod ledger;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CliAction {
    Help,
    Version,
    Run { output: PathBuf },
}

pub(crate) fn parse_cli_args(args: &[String]) -> Result<CliAction> {
    let rest = args.get(1..).unwrap_or(&[]);
    if rest.is_empty() {
        return Ok(CliAction::Help);
    }
    if rest.len() == 1 && matches!(rest[0].as_str(), "-h" | "--help") {
        return Ok(CliAction::Help);
    }
    if rest.len() == 1 && matches!(rest[0].as_str(), "-V" | "--version") {
        return Ok(CliAction::Version);
    }
    let mut output: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < rest.len() {
        let arg = &rest[i];
        if arg == "--output" {
            if output.is_some() {
                return Err("duplicate --output".into());
            }
            i += 1;
            let value = rest.get(i).ok_or("missing value for --output")?;
            if value.is_empty() || value.starts_with('-') {
                return Err("invalid --output value".into());
            }
            output = Some(PathBuf::from(value));
            i += 1;
        } else if let Some(value) = arg.strip_prefix("--output=") {
            if output.is_some() {
                return Err("duplicate --output".into());
            }
            if value.is_empty() || value.starts_with('-') {
                return Err("invalid --output value".into());
            }
            output = Some(PathBuf::from(value));
            i += 1;
        } else {
            return Err(format!("unknown or unsupported argument: {arg}; try --help").into());
        }
    }
    let output = output.ok_or("--output NEW_DIR is required (try --help)")?;
    Ok(CliAction::Run { output })
}

fn help_text() -> String {
    format!(
        "kerneldump {}\n\nUsage:\n  kerneldump --output <NEW_DIR>\n\nOptions:\n  --output <NEW_DIR>  New output directory for memory.lime, ranges.jsonl, and manifest.json\n  -h, --help          Show help and exit\n  -V, --version       Show version and exit\n\nSingle unified workflow:\n  1. Preflight check (storage contract, BTF kernel/VMA layout, kcore/kpageflags probe)\n  2. PFN-selective sparse LiME capture with deterministic node-wide code/network/unlinked-cache retention\n  3. Inline fast structural verification (headers, ledger hashes, counters, logical file bounds)\n\nExit 0 confirms complete acquisition for policy, durable publication, and structural verification; exit 2 means incomplete.",
        env!("CARGO_PKG_VERSION")
    )
}

fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().collect();
    let output = match parse_cli_args(&args)? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(true);
        }
        CliAction::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            return Ok(true);
        }
        CliAction::Run { output } => output,
    };
    if output.symlink_metadata().is_ok() {
        return Err(format!("output path already exists: {}", output.display()).into());
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Unified Step 1: Preflight storage contract, BTF layouts, and kcore/kpageflags.
    let mut memory = source::preflight(parent)?;
    memory.add_clock_context(clock_pair());
    // Unified Step 2: Acquire PFN-selective sparse LiME payload + ledger + manifest.
    let m = capture::acquire(
        memory,
        &output,
        source::Scope::KernelFocused,
        4 * 1024 * 1024,
        2,
    )?;
    // Unified Step 3: Inline fast structural verification (headers, ledger hashes, counters, bounds).
    let verified = if !m["artifact"].is_null() {
        Some(verify::verify_fast(&output)?)
    } else {
        None
    };
    let verified_ok = verified
        .as_ref()
        .is_some_and(|v| v["verified"].as_bool() == Some(true));
    let manifest_path = output.join("manifest.json");
    let manifest_sha256 = std::fs::read(&manifest_path).ok().map(|b| sha(&b));
    let payload_bytes = m["payload_bytes"].as_u64().unwrap_or(0);
    println!(
        "{}",
        json!({
            "status": m["status"],
            "completeness": if m["status"] == "complete_for_policy" { "complete" } else { "incomplete" },
            "output": output,
            "verification_mode": if verified.is_some() { "fast_structural" } else { "skipped" },
            "verified": verified_ok,
            "payload_hash_verified": false,
            "lime_bytes": m["file_bytes"],
            "payload_bytes": m["payload_bytes"],
            "file_bytes": m["file_bytes"],
            "retained_pages": payload_bytes / source::PAGE,
            "allocated_file_bytes": m["allocated_file_bytes"],
            "sparse_zero_hole_bytes": m["sparse_zero_hole_bytes"],
            "policy_excluded_bytes": m["policy_excluded_bytes"],
            "unavailable_bytes": m["unavailable_bytes"],
            "unprocessed_bytes": m["unprocessed_bytes"],
            "manifest_sha256": manifest_sha256,
            "manifest": manifest_path,
            "elapsed_s": m["elapsed_s"],
            "errors": m["errors"],
        })
    );
    Ok(m["status"] == "complete_for_policy" && verified_ok)
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
