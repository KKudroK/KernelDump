//! Linux output safety: pin private directories, reject symlink components and
//! publish without replacing a destination. Other processes with the same UID
//! or privileged filesystem access remain outside this protection boundary.
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
};
use std::path::{Component, Path, PathBuf};

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in output path"))
}
fn child_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = cstring(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_directory(path: &Path) -> io::Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => (),
            Component::ParentDir => file = child_directory(&file, OsStr::new(".."))?,
            Component::Normal(name) => file = child_directory(&file, name)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported output path prefix",
                ));
            }
        }
    }
    Ok(file)
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
pub struct OutputDir {
    directory: File,
    parent: File,
    requested: PathBuf,
}
impl OutputDir {
    pub fn create(requested: &Path) -> io::Result<Self> {
        let name = match requested.components().next_back() {
            Some(Component::Normal(name)) => name,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "output must name a new directory",
                ));
            }
        };
        let parent_path = requested
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = open_directory(parent_path)?;
        let name_c = cstring(name)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = child_directory(&parent, name)?;
        let result = Self {
            directory,
            parent,
            requested: requested.to_path_buf(),
        };
        result.verify_location()?;
        Ok(result)
    }
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }
    #[allow(dead_code)]
    pub fn parent(&self) -> &File {
        &self.parent
    }
    pub fn verify_location(&self) -> io::Result<()> {
        let pinned = self.directory.metadata()?;
        let current = open_directory(&self.requested)?.metadata()?;
        if !same(&pinned, &current)
            || !current.is_dir()
            || current.uid() != unsafe { libc::geteuid() }
            || current.mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "output directory changed identity, owner or private permissions",
            ));
        }
        Ok(())
    }
    pub fn sync(&self) -> io::Result<()> {
        self.directory.sync_all()?;
        self.parent.sync_all()?;
        self.verify_location()
    }
}
pub fn check_file(path: &Path, owned: &File) -> io::Result<()> {
    let original = owned.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !original.is_file()
        || !named.is_file()
        || !same(&original, &named)
        || original.uid() != unsafe { libc::geteuid() }
        || original.mode() & 0o077 != 0
        || original.nlink() != 1
    {
        return Err(io::Error::other(
            "output path no longer names the original private single-link file",
        ));
    }
    Ok(())
}
pub fn publish_file(source: &Path, destination: &Path, owned: &File) -> io::Result<()> {
    check_file(source, owned)?;
    let source = cstring(source.as_os_str())?;
    let destination = cstring(destination.as_os_str())?;
    // Fail closed on unsupported kernels/filesystems. Never fall back to an
    // existence check followed by an overwriting rename.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn remove_owned(path: &Path, owned: &File) -> io::Result<()> {
    check_file(path, owned)?;
    fs::remove_file(path)
}

pub fn check_available_space(path: &Path, required_bytes: u64) -> io::Result<u64> {
    let target = if path.exists() {
        path
    } else {
        path.parent().filter(|p| p.exists()).unwrap_or(Path::new("."))
    };
    let c_path = cstring(target.as_os_str())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let available_bytes = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
    if available_bytes < required_bytes {
        return Err(io::Error::other(format!(
            "insufficient disk space on target filesystem: requires at least {} MiB, but only {} MiB available",
            required_bytes / (1024 * 1024),
            available_bytes / (1024 * 1024)
        )));
    }
    Ok(available_bytes)
}

pub fn advise_dontneed(file: &File, offset: i64, len: i64) -> io::Result<()> {
    let rc = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            offset,
            len,
            libc::POSIX_FADV_DONTNEED,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

pub fn advise_sequential(file: &File, offset: i64, len: i64) -> io::Result<()> {
    let rc = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            offset,
            len,
            libc::POSIX_FADV_SEQUENTIAL,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "collector_output_unit_{}_{}",
                std::process::id(),
                crate::now()
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn file(path: &Path, bytes: &[u8]) -> File {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        f
    }
    #[test]
    fn publication_never_overwrites_existing_destination() {
        let t = Temp::new();
        let from = t.0.join("core.partial");
        let to = t.0.join("core");
        let f = file(&from, b"new");
        let _old = file(&to, b"preserve");
        assert!(publish_file(&from, &to, &f).is_err());
        assert_eq!(fs::read(&to).unwrap(), b"preserve");
        assert_eq!(fs::read(&from).unwrap(), b"new");
    }
    #[test]
    fn publication_does_not_replace_destination_symlink() {
        let t = Temp::new();
        let from = t.0.join("core.partial");
        let to = t.0.join("core");
        let victim = t.0.join("victim");
        let f = file(&from, b"new");
        let _victim = file(&victim, b"preserve");
        symlink(&victim, &to).unwrap();
        assert!(publish_file(&from, &to, &f).is_err());
        assert!(fs::symlink_metadata(&to).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"preserve");
    }
    #[test]
    fn replaced_source_and_reserve_are_never_published_or_removed() {
        let t = Temp::new();
        let from = t.0.join("partial");
        let f = file(&from, b"original");
        fs::rename(&from, t.0.join("saved")).unwrap();
        let _other = file(&from, b"unrelated");
        assert!(publish_file(&from, &t.0.join("final"), &f).is_err());
        assert!(remove_owned(&from, &f).is_err());
        assert_eq!(fs::read(&from).unwrap(), b"unrelated");
    }
    #[test]
    fn parent_symlink_is_rejected_before_directory_creation() {
        let t = Temp::new();
        fs::create_dir(t.0.join("real")).unwrap();
        symlink(t.0.join("real"), t.0.join("link")).unwrap();
        assert!(OutputDir::create(&t.0.join("link/capture")).is_err());
        assert!(!t.0.join("real/capture").exists());
    }
    #[test]
    fn pinned_output_never_follows_a_replaced_directory_path() {
        let t = Temp::new();
        let requested = t.0.join("capture");
        let output = OutputDir::create(&requested).unwrap();
        let moved = t.0.join("moved");
        fs::rename(&requested, &moved).unwrap();
        let unrelated = t.0.join("unrelated");
        fs::create_dir(&unrelated).unwrap();
        symlink(&unrelated, &requested).unwrap();
        assert!(output.verify_location().is_err());
        let _f = file(&output.path().join("data"), b"captured");
        assert_eq!(fs::read(moved.join("data")).unwrap(), b"captured");
        assert!(!unrelated.join("data").exists());
    }
}
