mod capture;
mod safe_output;
mod source;
#[cfg(test)]
mod tests;
mod verify;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
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
fn run() -> Result<bool> {
    use source::Memory;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|s| s == "--help") {
        #[cfg(not(feature = "development-options"))]
        {
            println!(
                "kerneldump {}\nUsage:\n  kerneldump check [--target-dir PATH] [--json]\n  kerneldump capture --output NEW_DIR [--request-id ID]\n  kerneldump probe\n  kerneldump verify OUTPUT_DIR\n\nStandalone Rust live physical LiME acquisition for Linux x86-64/4KiB.\nCaptures a conservative kernel-focused PFN selection with explicit exclusions.\nExcludes user/cache/free PFNs; retains SLAB, page tables and ambiguous PFNs.\nA narrow free-only SLAB boundary exception supports bounded analyzer reads.\nNot atomic, not entire RAM, and not a strict kernel-only guarantee.\nBuffering, parallel writing and durable publication are managed internally.\nCaller determines invocation time and incident policy. No security settings are changed.\nExit 0 confirms complete acquisition for the recorded policy and durable publication; preserve stderr on failure.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(true);
        }
        #[cfg(feature = "development-options")]
        {
            println!(
                "kerneldump {}\n\nUsage:\n  kerneldump check [--target-dir PATH] [--json]\n  kerneldump probe\n  kerneldump capture --output NEW_DIR [--scope full-ram|kernel-focused]\n                      [--chunk-mib 1..16] [--queue-depth 1..16]\n                      [--request-id ID]\n  kerneldump verify OUTPUT_DIR\n\nStandalone Rust Linux x86-64/4KiB live physical LiME acquisition.\nDefaults: kernel-focused, chunk1MiB, queue2. Requires readable kcore/kpageflags and\nunmasked page_offset_base/linux_banner; no security settings are changed.\nNot atomic, not a kernel-only guarantee. No incident/trigger/round policy.\nExit0 confirms successful policy acquisition and durability;2 means incomplete.\nAn in-flight kernel I/O call can delay cooperative cancellation.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(true);
        }
    }
    match args[0].as_str() {
        "check" => {
            let mut target_dir = None;
            let mut json_mode = false;
            for arg in &args[1..] {
                if arg == "--json" {
                    json_mode = true;
                } else if arg.starts_with("--target-dir=") {
                    target_dir = Some(PathBuf::from(&arg["--target-dir=".len()..]));
                } else if target_dir.is_none() && !arg.starts_with('-') {
                    target_dir = Some(PathBuf::from(arg));
                }
            }
            let report = source::check_readiness(target_dir.as_deref())?;
            let ready = report["ready"].as_bool().unwrap_or(false);
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kerneldump system readiness check (Linux {}):", report["kernel_release"]);
                if let Some(checks) = report["checks"].as_array() {
                    for c in checks {
                        let passed = c["passed"].as_bool().unwrap_or(false);
                        let symbol = if passed { "[\x1b[32mPASS\x1b[0m]" } else { "[\x1b[31mFAIL\x1b[0m]" };
                        println!("  {} {:<18} : {}", symbol, c["name"].as_str().unwrap_or(""), c["detail"].as_str().unwrap_or(""));
                    }
                }
                println!();
                if ready {
                    println!("\x1b[32mStatus: READY for live kernel memory acquisition.\x1b[0m");
                } else {
                    println!("\x1b[31mStatus: NOT READY. Please address failed checks above.\x1b[0m");
                }
            }
            Ok(ready)
        }
        "probe" if args.len() == 1 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&source::Source::open()?.info())?
            );
            Ok(true)
        }
        "verify" if args.len() == 2 => {
            println!("{}", verify::verify(Path::new(&args[1]))?);
            Ok(true)
        }
        "capture" => {
            let mut output = None;
            let mut scope = source::Scope::KernelFocused;
            let mut chunk = 1usize;
            let mut depth = 2usize;
            let mut request_id = format!("{}-{}", std::process::id(), now());
            for pair in args[1..].chunks(2) {
                if pair.len() != 2 {
                    return Err("option is missing its value".into());
                }
                match pair[0].as_str() {
                    "--output" => {
                        if output.is_some() {
                            return Err("duplicate output".into());
                        }
                        output = Some(PathBuf::from(&pair[1]));
                    }
                    "--scope" if cfg!(feature = "development-options") => {
                        scope = match pair[1].as_str() {
                            "full-ram" => source::Scope::FullRam,
                            "kernel-focused" => source::Scope::KernelFocused,
                            _ => return Err("invalid scope".into()),
                        }
                    }
                    "--chunk-mib" if cfg!(feature = "development-options") => {
                        chunk = pair[1].parse()?
                    }
                    "--queue-depth" if cfg!(feature = "development-options") => {
                        depth = pair[1].parse()?
                    }
                    "--request-id" => request_id = pair[1].clone(),
                    _ => return Err(format!("unknown option: {}", pair[0]).into()),
                }
            }
            if !(1..=16).contains(&chunk) || !(1..=16).contains(&depth) {
                return Err("chunk-mib and queue-depth must be1..16".into());
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
            let mut memory = source::Source::open()?;
            memory.add_context(request_id, clock_pair());
            let m = capture::acquire(memory, &output, scope, chunk * 1024 * 1024, depth)?;
            println!(
                "{}",
                json!({"status":m["status"],"payload_bytes":m["payload_bytes"],"policy_excluded_bytes":m["policy_excluded_bytes"],"unavailable_bytes":m["unavailable_bytes"],"unprocessed_bytes":m["unprocessed_bytes"],"elapsed_s":m["elapsed_s"],"errors":m["errors"],"manifest":output.join("manifest.json")})
            );
            Ok(m["status"] == "complete_for_policy")
        }
        _ => Err("invalid command; use --help".into()),
    }
}
fn main() {
    unsafe {
        libc::signal(libc::SIGINT, interrupted as *const () as usize);
        libc::signal(libc::SIGTERM, interrupted as *const () as usize);
    }
    match run() {
        Ok(true) => (),
        Ok(false) => std::process::exit(2),
        Err(e) => {
            eprintln!("kerneldump: {e}");
            std::process::exit(1)
        }
    }
}
