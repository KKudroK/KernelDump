use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs, path::Path, process::Command};

fn files(path: &Path, into: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).expect("read build inputs") {
        let path = entry.expect("build input entry").path();
        if path.is_dir() {
            files(&path, into);
        } else {
            into.push(path);
        }
    }
}
fn main() {
    let mut inputs = Vec::new();
    files(Path::new("src"), &mut inputs);
    for name in ["Cargo.toml", "Cargo.lock", "build.rs", ".cargo/config.toml"] {
        inputs.push(name.into());
    }
    let mut hashes = BTreeMap::new();
    for path in inputs {
        println!("cargo:rerun-if-changed={}", path.display());
        hashes.insert(
            path.to_string_lossy().replace('\\', "/"),
            format!(
                "{:x}",
                Sha256::digest(fs::read(path).expect("hash source input"))
            ),
        );
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=vendor");
    let mut deps = Vec::new();
    files(Path::new("vendor"), &mut deps);
    deps.sort();
    let mut dep_hash = Sha256::new();
    for path in deps {
        dep_hash.update(path.to_string_lossy().replace('\\', "/"));
        dep_hash.update([0]);
        dep_hash.update(Sha256::digest(fs::read(path).expect("hash vendored input")));
    }
    let compiler = Command::new(env::var_os("RUSTC").expect("RUSTC"))
        .arg("-Vv")
        .output()
        .expect("rustc version");
    assert!(compiler.status.success());
    let features: Vec<_> = env::vars()
        .filter_map(|(k, _)| {
            k.strip_prefix("CARGO_FEATURE_")
                .map(|v| v.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    let info = serde_json::json!({
        "schema":2, "package":env::var("CARGO_PKG_NAME").unwrap(),
        "version":env::var("CARGO_PKG_VERSION").unwrap(),
        "target":env::var("TARGET").unwrap(), "profile":env::var("PROFILE").unwrap(),
        "features":features, "compiler":String::from_utf8(compiler.stdout).unwrap().trim(),
        "source_sha256":hashes, "vendor_tree_sha256":format!("{:x}", dep_hash.finalize()),
        "binary_hash_semantics":"runtime_executable_sha256 is read from /proc/self/exe at invocation; final binary hash is never embedded in itself"
    });
    fs::write(
        Path::new(&env::var_os("OUT_DIR").unwrap()).join("build_info.json"),
        serde_json::to_vec(&info).unwrap(),
    )
    .unwrap();
}
