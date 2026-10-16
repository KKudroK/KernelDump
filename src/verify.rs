use crate::{Result, sha, source::PAGE};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};
// Bound bytes before JSON deserialization, including a file that grows after
// metadata inspection. This is an input-size bound, not a total RSS guarantee.
pub(crate) const MANIFEST_LIMIT: u64 = 16 * 1024 * 1024;
fn manifest(path: &Path) -> Result<Value> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    require(metadata.is_file(), "manifest must be a regular file")?;
    require(
        metadata.len() <= MANIFEST_LIMIT,
        "manifest exceeds 16MiB bound",
    )?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_LIMIT + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 <= MANIFEST_LIMIT,
        "manifest exceeds 16MiB bound",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn require(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(msg.to_string().into())
    }
}
pub fn verify(output: &Path) -> Result<Value> {
    let m = manifest(&output.join("manifest.json"))?;
    require(m["schema"] == 2, "requires Rust schema2 manifest")?;
    require(
        matches!(m["scope"].as_str(), Some("kernel-focused" | "full-ram")),
        "invalid acquisition scope",
    )?;
    require(
        matches!(
            m["status"].as_str(),
            Some("complete_for_policy" | "partial" | "failed")
        ),
        "invalid acquisition status",
    )?;
    let artifact = m["artifact"].as_str().ok_or("missing artifact")?;
    require(
        matches!(artifact, "memory.lime" | "memory.lime.partial"),
        "invalid artifact path",
    )?;
    let chunk = m["chunk_bytes"].as_u64().ok_or("missing chunk bound")?;
    require(
        chunk > 0 && chunk <= 16 * 1024 * 1024,
        "invalid chunk bound",
    )?;
    let ram: Vec<(u64, u64)> = serde_json::from_value(m["ram_ranges"].clone())?;
    require(
        !ram.is_empty()
            && ram
                .iter()
                .all(|(a, b)| a < b && a % PAGE == 0 && b % PAGE == 0)
            && ram.windows(2).all(|w| w[0].1 <= w[1].0),
        "invalid RAM ledger",
    )?;
    let expected = ram
        .iter()
        .try_fold(0u64, |sum, (a, b)| sum.checked_add(b - a))
        .ok_or("RAM sum overflow")?;
    let mut file = File::open(output.join(artifact))?;
    let ledger = BufReader::new(File::open(output.join("ranges.jsonl"))?);
    let mut hash = Sha256::new();
    let mut ledger_hash = Sha256::new();
    let mut offset = 0u64;
    let mut payload = 0u64;
    let mut excluded = 0u64;
    let mut unavailable = 0u64;
    let mut ranges = 0u64;
    let mut ram_index = 0usize;
    let mut cursor = ram[0].0;
    // Limit each JSONL record: corrupt metadata must not cause an unbounded allocation.
    let mut ledger = ledger;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = ledger.by_ref().take(131073).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        require(
            n <= 131072 && line.last() == Some(&b'\n'),
            "oversized or truncated range record",
        )?;
        ledger_hash.update(&line);
        let row: Value = serde_json::from_slice(&line)?;
        let start = row["physical_start"]
            .as_u64()
            .ok_or("missing range address")?;
        let size = row["bytes"].as_u64().ok_or("missing range length")?;
        while ram_index < ram.len() && cursor == ram[ram_index].1 {
            ram_index += 1;
            if ram_index < ram.len() {
                cursor = ram[ram_index].0;
            }
        }
        require(
            ram_index < ram.len()
                && start == cursor
                && size > 0
                && size <= chunk
                && size % PAGE == 0
                && start
                    .checked_add(size)
                    .is_some_and(|e| e <= ram[ram_index].1),
            "coverage gap, overlap or out-of-RAM range",
        )?;
        if let Some(runs) = row.get("flags_rle_pages_u64") {
            let runs: Vec<(u64, u64)> = serde_json::from_value(runs.clone())?;
            let mut pages = 0u64;
            let mut flags_hash = Sha256::new();
            for (count, flags) in runs {
                require(count > 0 && count <= size / PAGE, "invalid flag run length")?;
                pages = pages.checked_add(count).ok_or("flag run overflow")?;
                require(pages <= size / PAGE, "flag runs exceed range")?;
                for _ in 0..count {
                    flags_hash.update(flags.to_le_bytes());
                }
            }
            require(pages == size / PAGE, "flag coverage mismatch")?;
            require(
                row["flags_sha256"] == format!("{:x}", flags_hash.finalize()),
                "flags hash mismatch",
            )?;
        }
        match row["status"].as_str() {
            Some("selected") => {
                require(
                    row["file_offset"].as_u64() == Some(offset),
                    "ledger/file offset mismatch",
                )?;
                let mut header = [0u8; 32];
                file.read_exact(&mut header)?;
                require(
                    header == crate::capture::lime_header(start, size)?,
                    "LiME header/address mismatch",
                )?;
                let mut body = vec![0u8; size as usize];
                file.read_exact(&mut body)?;
                require(
                    row["sha256"].as_str() == Some(sha(&body).as_str()),
                    "payload hash mismatch",
                )?;
                hash.update(header);
                hash.update(&body);
                offset += 32 + size;
                payload += size;
            }
            Some("policy_excluded") => {
                require(
                    m["scope"] == "kernel-focused",
                    "policy exclusion in full RAM mode",
                )?;
                excluded += size;
            }
            Some("unsafe_pfn" | "unmapped") => unavailable += size,
            _ => return Err("unknown coverage classification".into()),
        }
        cursor += size;
        ranges += 1;
    }
    let mut extra = [0u8; 1];
    require(file.read(&mut extra)? == 0, "unaccounted trailing payload")?;
    require(
        m["ranges_sha256"].as_str() == Some(format!("{:x}", ledger_hash.finalize()).as_str()),
        "ledger hash mismatch",
    )?;
    let digest = format!("{:x}", hash.finalize());
    require(
        m["lime_sha256"].as_str() == Some(&digest),
        "LiME hash mismatch",
    )?;
    let accounted = payload + excluded + unavailable;
    require(
        m["payload_bytes"] == payload
            && m["policy_excluded_bytes"] == excluded
            && m["unavailable_bytes"] == unavailable
            && m["ranges"] == ranges
            && m["file_bytes"] == offset,
        "manifest counters mismatch",
    )?;
    require(
        m["expected_ram_bytes"] == expected
            && m["accounted_bytes"] == accounted
            && m["unprocessed_bytes"] == expected - accounted,
        "coverage counters mismatch",
    )?;
    let processed_end = if ranges == 0 { 0 } else { cursor };
    let unprocessed = ram
        .iter()
        .filter_map(|&(a, b)| {
            let start = a.max(processed_end);
            (start < b)
                .then(|| json!({"physical_start":start,"bytes":b-start,"status":"unprocessed"}))
        })
        .collect::<Vec<_>>();
    require(
        m["unprocessed_ranges"] == json!(unprocessed),
        "unprocessed physical range ledger mismatch",
    )?;
    if m["status"] == "complete_for_policy" {
        require(
            accounted == expected
                && unavailable == 0
                && m["errors"].as_array().is_some_and(|v| v.is_empty())
                && artifact == "memory.lime",
            "false complete status",
        )?;
    }
    Ok(
        json!({"verified":true,"status":m["status"],"payload_bytes":payload,"lime_sha256":digest,"coverage_ranges":ranges}),
    )
}
