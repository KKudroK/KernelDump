//! Optional acquisition scope. A failed Pod lookup never becomes node scope.
use crate::{CANCEL, Result, now};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::Path,
    sync::atomic::Ordering,
};

const MAX_PROC: usize = 65536;
const MAX_TARGETS: usize = 4096;
const MAX_BYTES: usize = 32 * 1024 * 1024;

pub fn uid(value: &str) -> Result<String> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("--pod requires a full Pod UID UUID, not a name or prefix".into());
    }
    Ok(value.to_ascii_lowercase())
}
fn pod_segment(s: &str, uid: &str) -> bool {
    let u = uid.replace('-', "_");
    s == format!("pod{uid}")
        || s == format!("pod{u}")
        || s.ends_with(&format!("-pod{u}.slice"))
        || s.ends_with(&format!("-pod{uid}.slice"))
}
fn membership(text: &str, uid: &str) -> Result<Option<String>> {
    let mut paths = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line.splitn(3, ':').collect();
        if fields.len() != 3 || fields[0].parse::<u32>().is_err() || !fields[2].starts_with('/') {
            return Err("malformed proc cgroup entry".into());
        }
        if fields[0] == "0" && fields[1].is_empty() {
            return Ok(fields[2]
                .split('/')
                .any(|s| pod_segment(s, uid))
                .then(|| fields[2].to_string()));
        }
        if fields[2].split('/').any(|s| pod_segment(s, uid)) {
            paths.push(fields[2].to_string());
        }
    }
    paths.sort();
    paths.dedup();
    if paths.len() > 1 {
        return Err("ambiguous Pod membership across cgroup controllers".into());
    }
    Ok(paths.pop())
}
pub fn start_ticks(stat: &str) -> Result<u64> {
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "invalid proc stat start time".into())
}
fn text(path: &Path, limit: usize) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("Pod scope proc read exceeds bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn gone(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pid: u32,
    pub tgid: u32,
    pub start_ticks: u64,
    pub cgroup: String,
}
impl Identity {
    fn json(&self) -> Value {
        json!({"pid":self.pid,"tgid":self.tgid,"start_ticks":self.start_ticks,"cgroup":self.cgroup})
    }
    fn path(&self) -> std::path::PathBuf {
        format!("/proc/{}/task/{}", self.tgid, self.pid).into()
    }
    fn current(&self, uid: &str, bytes: &Cell<usize>) -> Result<()> {
        let p = self.path();
        let read = |name, limit| -> Result<String> {
            let result = text(&p.join(name), limit);
            bytes.set(bytes.get() + result.as_ref().map_or(limit, |s| s.len()));
            result
        };
        let a = start_ticks(&read("stat", 8192)?)?;
        let cg = membership(&read("cgroup", 32768)?, uid)?;
        let b = start_ticks(&read("stat", 8192)?)?;
        if a != self.start_ticks || a != b || cg.as_ref() != Some(&self.cgroup) {
            return Err("target process reused, exited or changed Pod membership".into());
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct PodScope {
    pub uid: String,
    pub boot_id: String,
    pub processes: BTreeMap<u32, Identity>,
    pub threads: BTreeMap<u32, Identity>,
    pub report: Value,
    validation_bytes: Cell<usize>,
    validation_ns: Cell<u64>,
}
impl PodScope {
    pub fn discover(value: &str, deadline: u64) -> Result<Self> {
        Self::discover_at(value, deadline, Path::new("/proc"))
    }
    fn discover_at(value: &str, deadline: u64, proc: &Path) -> Result<Self> {
        let uid = uid(value)?;
        let begin = now();
        let mut reads = 0;
        let mut examined = 0;
        let mut processes = BTreeMap::new();
        let mut threads = BTreeMap::new();
        let mut exited = 0;
        let mut read = |path: &Path, limit| -> Result<String> {
            if now() >= deadline || CANCEL.load(Ordering::Relaxed) || reads + limit > MAX_BYTES {
                return Err("Pod census deadline/cancel/metadata limit".into());
            }
            let value = text(path, limit);
            reads += value.as_ref().map_or(limit, |s| s.len());
            value
        };
        let boot_id = read(&proc.join("sys/kernel/random/boot_id"), 128)?
            .trim()
            .to_string();
        for entry in fs::read_dir(proc)? {
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            examined += 1;
            if examined > MAX_PROC {
                return Err("Pod census process enumeration limit".into());
            }
            let p = entry.path();
            let result = (|| -> Result<()> {
                let cg = read(&p.join("cgroup"), 32768)?;
                let Some(cgroup) = membership(&cg, &uid)? else {
                    return Ok(());
                };
                let first = start_ticks(&read(&p.join("stat"), 8192)?)?;
                let mut members = Vec::new();
                for task in fs::read_dir(p.join("task"))? {
                    let task = task?;
                    let Ok(tid) = task.file_name().to_string_lossy().parse::<u32>() else {
                        continue;
                    };
                    if threads.len() + members.len() >= MAX_TARGETS {
                        return Err("Pod thread limit".into());
                    }
                    let tp = task.path();
                    let one = (|| -> Result<Option<Identity>> {
                        let start = start_ticks(&read(&tp.join("stat"), 8192)?)?;
                        let cg = membership(&read(&tp.join("cgroup"), 32768)?, &uid)?;
                        let end = start_ticks(&read(&tp.join("stat"), 8192)?)?;
                        if start != end {
                            return Err("thread replaced during Pod census".into());
                        }
                        Ok(cg.map(|cgroup| Identity {
                            pid: tid,
                            tgid: pid,
                            start_ticks: start,
                            cgroup,
                        }))
                    })();
                    match one {
                        Ok(Some(id)) => members.push(id),
                        Ok(None) => (),
                        Err(e) if gone(e.as_ref()) => exited += 1,
                        Err(e) => return Err(e),
                    }
                }
                if start_ticks(&read(&p.join("stat"), 8192)?)? != first
                    || membership(&read(&p.join("cgroup"), 32768)?, &uid)?.as_ref() != Some(&cgroup)
                {
                    return Err("process changed during Pod census".into());
                }
                let id = Identity {
                    pid,
                    tgid: pid,
                    start_ticks: first,
                    cgroup,
                };
                if !members.contains(&id) {
                    return Err("Pod leader absent from thread census".into());
                }
                processes.insert(pid, id);
                for id in members {
                    threads.insert(id.pid, id);
                }
                Ok(())
            })();
            match result {
                Ok(()) => (),
                Err(e) if gone(e.as_ref()) => exited += 1,
                Err(e) => return Err(e),
            }
        }
        if processes.is_empty() {
            return Err(
                "Pod has no visible live member processes; refusing node-wide fallback".into(),
            );
        }
        let report = json!({"pod_uid":uid,"boot_id":boot_id,"begin_ns":begin,"end_ns":now(),
            "processes_examined":examined,"disappeared_during_census":exited,"metadata_request_bound_bytes":reads,
            "processes":processes.values().map(Identity::json).collect::<Vec<_>>(),"threads":threads.values().map(Identity::json).collect::<Vec<_>>(),
            "selection":"exact cgroup Pod UID segment; current host process identities, not historical ownership",
            "limits":{"visible_processes":MAX_PROC,"target_threads":MAX_TARGETS,"metadata_request_bound_bytes":MAX_BYTES},
            "base_kernel_filter_unchanged":true});
        Ok(Self {
            uid,
            boot_id,
            processes,
            threads,
            report,
            validation_bytes: Cell::new(0),
            validation_ns: Cell::new(0),
        })
    }
    fn validate(&self, id: &Identity) -> Result<()> {
        if self.validation_bytes.get() + 49152 > 8 * 1024 * 1024
            || self.validation_ns.get() > 250_000_000
            || CANCEL.load(Ordering::Relaxed)
        {
            return Err("Pod identity validation budget exhausted".into());
        }
        let start = now();
        let result = id.current(&self.uid, &self.validation_bytes);
        self.validation_ns
            .set(self.validation_ns.get() + now() - start);
        result
    }
    pub fn validation_stats(&self) -> Value {
        json!({"accounted_bytes":self.validation_bytes.get(),"elapsed_ns":self.validation_ns.get(),
            "max_bytes":8*1024*1024,"max_ns":250_000_000,"scope":"per code/network identity validator; active proc reads are cooperative"})
    }
    pub fn validate_process(&self, pid: u32, start: u64) -> Result<()> {
        let id = self
            .processes
            .get(&pid)
            .ok_or("process outside requested Pod")?;
        if id.start_ticks != start {
            return Err("target process start time mismatch".into());
        }
        self.validate(id)
    }
    pub fn validate_thread(&self, pid: u32, boot_ns: u64) -> Result<&Identity> {
        let id = self
            .threads
            .get(&pid)
            .ok_or("thread outside requested Pod census")?;
        // Supported x86-64 USER_HZ is 100; proc stat uses start_boottime, not start_time.
        if unsafe { libc::sysconf(libc::_SC_CLK_TCK) } != 100
            || boot_ns / 10_000_000 != id.start_ticks
        {
            return Err("kernel/proc target identity mismatch".into());
        }
        self.validate(id)?;
        Ok(id)
    }
    pub fn finish(&self) -> Value {
        match Self::discover(&self.uid, now() + 500_000_000) {
            Ok(current) => {
                json!({"complete":current.boot_id==self.boot_id && current.processes==self.processes && current.threads==self.threads,
                "before":self.report,"after":current.report,"consistency":"Two bounded censuses, not an atomic snapshot; transient membership and ABA remain possible"})
            }
            Err(e) => json!({"complete":false,"before":self.report,"error":e.to_string()}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const UID: &str = "12345678-1234-1234-1234-123456789abc";
    #[test]
    fn strict_uid_and_boundary() {
        for s in [
            "",
            "foo",
            "12345678",
            "12345678-1234-1234-1234-123456789abz",
        ] {
            assert!(uid(s).is_err());
        }
        assert_eq!(uid(&UID.to_uppercase()).unwrap(), UID);
        assert!(pod_segment(&format!("pod{UID}"), UID));
        assert!(!pod_segment(&format!("pod{UID}-suffix"), UID));
        assert!(!pod_segment(&format!("prefixpod{UID}"), UID));
    }
    #[test]
    fn cgroup_v1_v2_and_systemd() {
        assert!(
            membership(&format!("0::/kubepods/burstable/pod{UID}/abc\n"), UID)
                .unwrap()
                .is_some()
        );
        let u = UID.replace('-', "_");
        assert!(membership(&format!("7:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{u}.slice/abc.scope\n"),UID).unwrap().is_some());
        assert_eq!(
            membership(&format!("0::/\n7:pids:/pod{UID}"), UID).unwrap(),
            None
        );
        assert!(membership(&format!("7:pids:/pod{UID}/a\n8:memory:/pod{UID}/b"), UID).is_err());
        assert!(membership("malformed", UID).is_err());
    }
    #[test]
    fn stat_name_is_not_tokenized() {
        let stat = format!("42 (a ) b) S {} 912", vec!["0"; 18].join(" "));
        assert_eq!(start_ticks(&stat).unwrap(), 912);
        assert!(start_ticks("42 broken").is_err());
    }
    #[test]
    fn wrong_pod_and_deadline_never_fallback() {
        assert!(PodScope::discover(UID, now()).is_err());
        assert!(PodScope::discover(UID, now() + 1_000_000_000).is_err());
    }
    #[test]
    fn census_selects_exact_pod_and_each_thread() {
        let root = std::env::temp_dir().join(format!(
            "kerneldump_pod_test_{}_{}",
            std::process::id(),
            now()
        ));
        fs::create_dir_all(root.join("sys/kernel/random")).unwrap();
        fs::write(root.join("sys/kernel/random/boot_id"), "boot-test").unwrap();
        let stat = |pid: u32| {
            format!(
                "{pid} (test ) name) S {} {}",
                vec!["0"; 18].join(" "),
                pid * 100
            )
        };
        for (pid, member) in [(100, true), (200, false)] {
            let p = root.join(pid.to_string());
            fs::create_dir_all(p.join("task")).unwrap();
            let cg = if member {
                format!("0::/kubepods/pod{UID}/container")
            } else {
                format!("0::/kubepods/pod{UID}-wrong/container")
            };
            fs::write(p.join("cgroup"), &cg).unwrap();
            fs::write(p.join("stat"), stat(pid)).unwrap();
            for tid in [pid, pid + 1] {
                let t = p.join("task").join(tid.to_string());
                fs::create_dir(&t).unwrap();
                fs::write(t.join("cgroup"), &cg).unwrap();
                fs::write(t.join("stat"), stat(tid)).unwrap();
            }
        }
        let scope = PodScope::discover_at(UID, now() + 1_000_000_000, &root).unwrap();
        assert_eq!(
            scope.processes.keys().copied().collect::<Vec<_>>(),
            vec![100]
        );
        assert_eq!(
            scope.threads.keys().copied().collect::<Vec<_>>(),
            vec![100, 101]
        );
        fs::write(root.join("100/cgroup"), "0::/moved").unwrap();
        assert!(PodScope::discover_at(UID, now() + 1_000_000_000, &root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
