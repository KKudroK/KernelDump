use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
};

fn executable_sha256() -> io::Result<String> {
    let mut file = File::open("/proc/self/exe")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub fn current() -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/build_info.json")))
            .expect("generated build metadata");
    match executable_sha256() {
        Ok(hash) => value["runtime_executable_sha256"] = serde_json::json!(hash),
        Err(e) => value["runtime_executable_hash_error"] = serde_json::json!(e.to_string()),
    }
    value
}
