use super::*;
use std::io::Write;
use std::os::unix::fs::FileExt;

pub(super) struct TestBtf {
    strings: Vec<u8>,
    records: Vec<u8>,
    count: u32,
}
impl TestBtf {
    pub(super) fn new() -> Self {
        Self {
            strings: vec![0],
            records: Vec::new(),
            count: 0,
        }
    }
    pub(super) fn name(&mut self, s: &str) -> u32 {
        let at = self.strings.len() as u32;
        self.strings.extend(s.as_bytes());
        self.strings.push(0);
        at
    }
    pub(super) fn record(&mut self, words: &[u32]) -> u32 {
        for v in words {
            self.records.extend(v.to_le_bytes())
        }
        self.count += 1;
        self.count
    }
    pub(super) fn int(&mut self, name: &str, size: u32) -> u32 {
        let n = self.name(name);
        self.record(&[n, 1 << 24, size, size * 8])
    }
    pub(super) fn structure(&mut self, name: &str, size: u32, fields: &[(&str, u32, u32)]) -> u32 {
        let n = self.name(name);
        let mut w = vec![n, (4 << 24) | fields.len() as u32, size];
        for (s, t, o) in fields {
            let field = self.name(s);
            w.extend([field, *t, *o * 8]);
        }
        self.record(&w)
    }
    pub(super) fn finish(self) -> Btf {
        let mut b = vec![0x9f, 0xeb, 1, 0];
        for v in [
            24,
            0,
            self.records.len() as u32,
            self.records.len() as u32,
            self.strings.len() as u32,
        ] {
            b.extend(v.to_le_bytes())
        }
        b.extend(self.records);
        b.extend(self.strings);
        Btf::parse(b).unwrap()
    }
}

fn network_btf() -> Btf {
    let mut b = TestBtf::new();
    let u8t = b.int("u8", 1);
    let u16t = b.int("u16", 2);
    let u32t = b.int("u32", 4);
    let ptr = b.record(&[0, 2 << 24, 0]);
    b.structure("files_struct", 8, &[("fdt", ptr, 0)]);
    b.structure(
        "fdtable",
        24,
        &[("max_fds", u32t, 0), ("fd", ptr, 8), ("open_fds", ptr, 16)],
    );
    b.structure("file", 32, &[("f_inode", ptr, 0), ("private_data", ptr, 8)]);
    b.structure("inode", 8, &[("i_mode", u16t, 0)]);
    b.structure("socket", 32, &[("file", ptr, 0), ("sk", ptr, 8)]);
    let common = b.structure("sock_common", 2, &[("skc_family", u16t, 0)]);
    let queue = b.structure("sk_buff_head", 16, &[("next", ptr, 0), ("prev", ptr, 8)]);
    b.structure(
        "sock",
        48,
        &[
            ("__sk_common", common, 0),
            ("sk_protocol", u16t, 2),
            ("sk_socket", ptr, 8),
            ("sk_receive_queue", queue, 16),
            ("sk_write_queue", queue, 32),
        ],
    );
    b.structure(
        "sk_buff",
        64,
        &[
            ("head", ptr, 0),
            ("data", ptr, 8),
            ("len", u32t, 16),
            ("data_len", u32t, 20),
            ("tail", u32t, 24),
            ("end", u32t, 28),
            ("next", ptr, 32),
        ],
    );
    let frag = b.structure(
        "skb_frag_t",
        16,
        &[
            ("bv_page", ptr, 0),
            ("bv_len", u32t, 8),
            ("bv_offset", u32t, 12),
        ],
    );
    let arr = b.record(&[0, 3 << 24, 0, frag, u32t, 1]);
    b.structure(
        "skb_shared_info",
        32,
        &[
            ("nr_frags", u8t, 0),
            ("frag_list", ptr, 8),
            ("frags", arr, 16),
        ],
    );
    b.finish()
}

#[test]
fn socket_witness_must_detect_changed_ownership() {
    for (changed_at, changed_value, n, valid) in [
        (0x300usize, 0u64, 8usize, false),
        (0x400, 0, 8, false),
        (0x100, 0, 8, false),
        (0x208, 0, 8, false),
        (0x210, 0, 8, false),
        (0x508, 0, 8, false),
        (0x700, 0, 8, false),
        (0x708, 0, 8, false),
        (0x808, 0, 8, false),
        (0x400, 3, 8, true),
        (0, 0, 8, true),
    ] {
        const BASE: u64 = 0xffff888000000000;
        let path = std::env::temp_dir().join(format!(
            "kerneldump_review_network_{}_{}",
            std::process::id(),
            now()
        ));
        let mut core = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut data = vec![0u8; 0x5000];
        let put = |data: &mut [u8], at: usize, value: u64, n: usize| {
            data[at..at + n].copy_from_slice(&value.to_le_bytes()[..n])
        };
        let files = BASE + 0x100;
        let table = BASE + 0x200;
        let array = BASE + 0x300;
        let bitmap = BASE + 0x400;
        let file = BASE + 0x500;
        let inode = BASE + 0x600;
        let socket = BASE + 0x700;
        let sk = BASE + 0x800;
        let skb = BASE + 0x1000;
        let bytes = BASE + 0x2000;
        put(&mut data, 0x50, files, 8);
        put(&mut data, 0x100, table, 8);
        put(&mut data, 0x200, 64, 4);
        put(&mut data, 0x208, array, 8);
        put(&mut data, 0x210, bitmap, 8);
        put(&mut data, 0x300, file, 8);
        put(&mut data, 0x400, 1, 8);
        put(&mut data, 0x500, inode, 8);
        put(&mut data, 0x508, socket, 8);
        put(&mut data, 0x600, 0xc000, 2);
        put(&mut data, 0x700, file, 8);
        put(&mut data, 0x708, sk, 8);
        put(&mut data, 0x800, 1, 2);
        put(&mut data, 0x808, socket, 8);
        put(&mut data, 0x810, skb, 8);
        put(&mut data, 0x820, sk + 32, 8);
        put(&mut data, 0x1000, bytes, 8);
        put(&mut data, 0x1008, bytes, 8);
        put(&mut data, 0x1010, 16, 4);
        put(&mut data, 0x1018, 16, 4);
        put(&mut data, 0x101c, 128, 4);
        put(&mut data, 0x1020, sk + 16, 8);
        data[0x2000..0x2010].fill(0x41);
        core.write_all(&data).unwrap();
        let segs = [Segment {
            offset: 0,
            va: BASE,
            pa: PAGE,
            bytes: data.len() as u64,
        }];
        let ram = [(PAGE, PAGE + data.len() as u64)];
        let mut plan = Resources::default();
        let mut scan = Scan {
            pod: None,
            target_seen: BTreeSet::new(),
            cache: cache::CacheState::default(),
            code_targets: vec![],
            btf: network_btf(),
            live: Live {
                core: &core,
                segs: &segs,
                ram: &ram,
                deadline: now() + 5_000_000_000,
                read_limit: MAX_READ_BYTES,
                read_bytes: Cell::new(0),
                calls: Cell::new(0),
                root: 0,
                levels: 4,
            },
            plan: &mut plan,
            fields: RefCell::new(HashMap::new()),
            vmemmap: BASE + 0x4000,
            page_size: 64,
            files: BTreeSet::new(),
            tables: BTreeSet::new(),
            tasks: 1,
            fd_refs: 0,
            sockets: 0,
            skbs: 0,
            policy_truncations: 0,
            task_identity: json!({"pid":42,"task":BASE,"start_time_ns":1}),
            task_checks: vec![Check {
                address: BASE + 0x50,
                bytes: files.to_le_bytes().to_vec(),
                mask: None,
            }],
        };
        scan.fdtable(files, 42).unwrap();
        assert_eq!(
            scan.task_checks.len(),
            1,
            "socket checks must not leak to the next file"
        );
        drop(scan);
        assert!(!plan.pages.is_empty());
        // Keep the task and payload alive while changing one ownership link.
        // Toggling only a different FD bit must preserve the target reference.
        core.write_all_at(&changed_value.to_le_bytes()[..n], changed_at as u64)
            .unwrap();
        let witness = plan.witness(PAGE, PAGE + data.len() as u64, true, |va, buf| {
            virtual_read(&core, &segs, va, buf)
        });
        let network: Vec<_> = witness
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["category"] == "network")
            .collect();
        assert!(!network.is_empty());
        assert!(
            network
                .iter()
                .any(|v| v["reference"]["role"] == "network_bytes")
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            network.iter().all(|v| v["same_fields"] == valid),
            "ownership mutation at {changed_at:x}"
        );
        assert_eq!(plan.finish()["complete"], valid);
    }
}
