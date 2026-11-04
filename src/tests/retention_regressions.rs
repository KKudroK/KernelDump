use super::*;
// Retention regressions. Synthetic inputs exercise the production writer/verifier.
struct DenseCode(Fake, usize);
impl Memory for DenseCode {
    fn info(&self) -> Value {
        self.0.info()
    }
    fn ram(&self) -> &[(u64, u64)] {
        self.0.ram()
    }
    fn chunk(&self, a: u64, b: u64, c: u64) -> Result<(u64, Option<u64>)> {
        self.0.chunk(a, b, c)
    }
    fn flags(&self, a: u64, b: u64) -> Result<Vec<u64>> {
        self.0.flags(a, b)
    }
    fn read(&self, a: u64, b: &mut [u8]) -> Result<()> {
        self.0.read(a, b)
    }
    fn code_pages(&self, a: u64, b: u64) -> Vec<u64> {
        (1..self.0.ram[0].1 / PAGE)
            .map(|p| p * PAGE)
            .filter(|p| a <= *p && *p < b)
            .collect()
    }
    fn code_witness(&self, a: u64, b: u64, _after: bool) -> Value {
        let rows:Vec<_>=self.code_pages(a,b).iter().flat_map(|pa|(0..self.1 as u64).map(move |reference|json!({
            "physical":pa,"pid":10000+reference%128,"start_ticks":12345678u64,"virtual":0x7f0000000000u64+pa+(reference/128)*0x100000,
            "file_device_inode":"08:01:123456789","file_offset":pa,"same_pfn":true,
            "pagemap_entry":(1u64<<63)|(*pa/PAGE),"observed_ns":1234567890123456u64
        }))).collect();
        json!(rows)
    }
    fn finish_code_pages(&self) -> Value {
        retention_result(true, (self.0.ram[0].1 - self.0.ram[0].0) / PAGE)
    }
}

#[test]
fn dense_reference_capture_must_verify() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.ram = vec![(PAGE, 33 * PAGE)];
    f.flags = vec![1 << 12; 32];
    // 128 processes, 32 shared anonymous executable pages, 4096 references:
    // below scan limits 256 descriptors / 4096 pages / 8192 references.
    let m = capture::acquire(
        DenseCode(f, 128),
        &t.out(),
        Scope::KernelFocused,
        1024 * 1024,
        2,
    )
    .unwrap();
    assert_eq!(m["status"], "complete_for_policy");
    let line = fs::read(t.out().join("ranges.jsonl")).unwrap();
    let result = verify::verify(&t.out());
    assert!(line.len() > 1024 * 1024);
    assert!(
        result.is_ok(),
        "a complete capture emitted by the writer must pass its own verifier"
    );
}

#[test]
fn verifier_rejects_false_complete_retention_status() {
    let t = Temp::new();
    let f = Fake::new();
    let mut m = capture::acquire(
        ResourceFake(f, false),
        &t.out(),
        Scope::KernelFocused,
        16384,
        2,
    )
    .unwrap();
    assert_eq!(m["status"], "partial");
    assert_eq!(m["read_stages"]["resource_retention"]["complete"], false);
    m["status"] = json!("complete_for_policy");
    m["errors"] = json!([]);
    m["artifact"] = json!("memory.lime");
    fs::rename(
        t.out().join("memory.lime.partial"),
        t.out().join("memory.lime"),
    )
    .unwrap();
    fs::write(
        t.out().join("manifest.json"),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    let result = verify::verify(&t.out());
    assert!(
        result.is_err(),
        "complete status must not contradict resource_retention.complete=false"
    );
}

#[test]
fn concentrated_references_on_one_page_round_trip() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.ram = vec![(PAGE, 2 * PAGE)];
    f.flags = vec![1 << 12];
    // 128 processes with aliases of one PFN, below 8192 total references.
    let m = capture::acquire(
        DenseCode(f, 8191),
        &t.out(),
        Scope::KernelFocused,
        1024 * 1024,
        2,
    )
    .unwrap();
    assert_eq!(m["status"], "complete_for_policy");
    let bytes = fs::metadata(t.out().join("ranges.jsonl")).unwrap().len();
    assert!(bytes > 1024 * 1024 && bytes <= crate::ledger::RECORD_LIMIT as u64);
    verify::verify(&t.out()).unwrap();
}

struct OversizedReference(Fake);
impl Memory for OversizedReference {
    fn info(&self) -> Value {
        self.0.info()
    }
    fn ram(&self) -> &[(u64, u64)] {
        self.0.ram()
    }
    fn chunk(&self, a: u64, b: u64, c: u64) -> Result<(u64, Option<u64>)> {
        self.0.chunk(a, b, c)
    }
    fn flags(&self, a: u64, b: u64) -> Result<Vec<u64>> {
        self.0.flags(a, b)
    }
    fn read(&self, a: u64, b: &mut [u8]) -> Result<()> {
        self.0.read(a, b)
    }
    fn code_pages(&self, a: u64, b: u64) -> Vec<u64> {
        (a <= PAGE && PAGE < b)
            .then_some(PAGE)
            .into_iter()
            .collect()
    }
    fn code_witness(&self, _a: u64, _b: u64, _after: bool) -> Value {
        json!([{"physical":PAGE,"same_pfn":true,"padding":"x".repeat(crate::ledger::RECORD_LIMIT)}])
    }
}

#[test]
fn excessive_metadata_fails_before_writing_unledgered_payload() {
    let t = Temp::new();
    let m = capture::acquire(
        OversizedReference(Fake::new()),
        &t.out(),
        Scope::KernelFocused,
        16384,
        2,
    )
    .unwrap();
    assert_eq!(m["status"], "failed");
    assert_eq!(m["file_bytes"], 0);
    assert_eq!(m["unledgered_payload_bytes"], 0);
    assert!(m["errors"].to_string().contains("range record exceeds"));
    verify::verify(&t.out()).unwrap();
}

#[test]
fn verifier_rejects_missing_invalid_and_contradictory_retention_sections() {
    let t = Temp::new();
    let original = capture(Fake::new(), &t, Scope::KernelFocused);
    let path = t.out().join("manifest.json");
    let mut variants = Vec::new();
    for name in ["code_page_retention", "resource_retention"] {
        let mut m = original.clone();
        m["read_stages"].as_object_mut().unwrap().remove(name);
        variants.push(m);
        for bad in [
            json!({"complete":false}),
            json!({"complete":"true"}),
            json!({"complete":true}),
        ] {
            let mut m = original.clone();
            m["read_stages"][name] = bad;
            variants.push(m);
        }
        for (key, bad) in [
            ("unread_candidate_pages", json!(1)),
            ("read_candidate_pages", json!(1)),
            ("issue_count", json!(1)),
            ("issues", json!([{"error":"changed"}])),
        ] {
            let mut report = retention_result(true, 0);
            report[key] = bad;
            let mut m = original.clone();
            m["read_stages"][name] = report;
            variants.push(m);
        }
    }
    let mut m = original.clone();
    m["source"]["pod_scope"] = json!({"pod_uid":"selected"});
    variants.push(m.clone());
    m["read_stages"]["resource_retention"]["pod_scope_validation"] = json!({"complete":false});
    variants.push(m);
    let mut m = original.clone();
    m["source"]["shared_retention_budget"] = json!({"candidate_pages":2,"selected_candidate_pages":2,
        "unselected_candidate_pages":1,"max_candidate_pages":4096});
    variants.push(m);
    for (i, m) in variants.iter().enumerate() {
        fs::write(&path, serde_json::to_vec(m).unwrap()).unwrap();
        assert!(
            verify::verify(&t.out()).is_err(),
            "accepted contradictory manifest {i}"
        );
    }
    fs::write(path, serde_json::to_vec(&original).unwrap()).unwrap();
    verify::verify(&t.out()).unwrap();
}

#[test]
fn legacy_policy_without_additional_retention_remains_verifiable() {
    let t = Temp::new();
    let mut m = capture(Fake::new(), &t, Scope::KernelFocused);
    m["filter"]["policy"] = json!("kernel-focused-v4");
    for name in ["code_page_retention", "resource_retention"] {
        m["read_stages"].as_object_mut().unwrap().remove(name);
    }
    fs::write(
        t.out().join("manifest.json"),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    verify::verify(&t.out()).unwrap();
}

#[test]
fn complete_manifest_cannot_hide_a_changed_ledger_witness() {
    let t = Temp::new();
    let mut f = Fake::new();
    f.ram = vec![(PAGE, 2 * PAGE)];
    f.flags = vec![1 << 12];
    let mut m = capture::acquire(DenseCode(f, 1), &t.out(), Scope::KernelFocused, 4096, 1).unwrap();
    let path = t.out().join("ranges.jsonl");
    let mut row: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    row["code_pages_after"][0]["same_pfn"] = json!(false);
    let bytes = crate::ledger::encode(&row).unwrap();
    m["ranges_sha256"] = json!(sha(&bytes));
    fs::write(path, bytes).unwrap();
    fs::write(
        t.out().join("manifest.json"),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    assert!(verify::verify(&t.out()).is_err());
}
