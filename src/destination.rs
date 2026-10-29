//! Files sbx writes for the operator: the report (`--report`) and the log
//! (`--log`). Their contents are trusted, so they must live where the
//! sandbox cannot reach:
//!
//! * The path is absolute and its directory canonical (no symlinks).
//! * Every directory from `/` down to the file's own belongs to root or to
//!   sbx's uid and is writable by nobody else. A sticky directory such as
//!   `/tmp` is allowed above that only if the next directory down belongs to
//!   root or sbx's uid, since then nobody else can rename it.
//! * When sbx is not root, the program runs as sbx's own uid, so only
//!   Landlock keeps it out: the directory must lie outside every fs rule.
//!
//! The directory is opened when sbx starts and files are created through
//! that descriptor only, with O_NOFOLLOW, never through the path again.

use crate::log::{errno, os_err};
use crate::policy::{LandlockAbi, Policy};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Owner and mode of one directory on the way to a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirMeta {
    pub uid: u32,
    pub mode: u32,
}

/// Whether the directories `chain` (from `/` down to the destination's own)
/// keep everyone but root and `euid` from replacing what is in them.
pub fn check_chain(chain: &[(PathBuf, DirMeta)], euid: u32) -> Result<(), String> {
    let trusted = |uid: u32| uid == 0 || uid == euid;
    for (i, (path, m)) in chain.iter().enumerate() {
        let p = path.display();
        if !trusted(m.uid) {
            return Err(format!(
                "{p} belongs to uid {}; every directory on the way must belong to root or uid {euid}",
                m.uid
            ));
        }
        if m.mode & 0o022 == 0 {
            continue;
        }
        // In a sticky directory only an entry's owner can rename it, and the
        // next directory's owner is checked on the next iteration.
        let sticky = m.mode & libc::S_ISVTX != 0;
        if !sticky || i + 1 == chain.len() {
            return Err(format!(
                "{p} is writable by others (mode {:o}); use a directory only root or uid {euid} can write",
                m.mode & 0o7777
            ));
        }
    }
    Ok(())
}

pub struct Destination {
    path: PathBuf,
    dir_path: PathBuf,
    dir: OwnedFd,
    name: CString,
}

impl Destination {
    /// Check the path and open its directory. `what` names the option.
    pub fn open(what: &str, path: &Path) -> Result<Destination, String> {
        let p = path.display();
        if !path.is_absolute() {
            return Err(format!("{what} {p}: the path must be absolute"));
        }
        let bytes = path.as_os_str().as_bytes();
        let (Some(dir), Some(Component::Normal(name))) = (path.parent(), path.components().next_back()) else {
            return Err(format!("{what} {p}: the path must name a file"));
        };
        if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
            return Err(format!("{what} {p}: the path must name a file"));
        }
        let canonical = std::fs::canonicalize(dir).map_err(|e| format!("{what} {p}: {}: {e}", dir.display()))?;
        if canonical != dir {
            return Err(format!(
                "{what} {p}: {} is not canonical: it resolves to {}; write the resolved path",
                dir.display(),
                canonical.display()
            ));
        }
        let mut chain = Vec::new();
        for d in dir.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let m = std::fs::symlink_metadata(d).map_err(|e| format!("{what} {p}: {}: {e}", d.display()))?;
            chain.push((
                d.to_path_buf(),
                DirMeta {
                    uid: m.uid(),
                    mode: m.mode(),
                },
            ));
        }
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        check_chain(&chain, euid).map_err(|e| format!("{what} {p}: {e}"))?;

        let cdir = CString::new(dir.as_os_str().as_bytes()).map_err(|_| format!("{what} {p}: NUL byte in the path"))?;
        // SAFETY: plain open of a NUL-terminated path; the fd is owned below.
        let fd = unsafe {
            libc::open(
                cdir.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(os_err(format!("{what} {p}: opening {}", dir.display())));
        }
        // SAFETY: fd is a new descriptor we own.
        let dirfd = unsafe { OwnedFd::from_raw_fd(fd) };
        let opened = File::from(dirfd.try_clone().map_err(|e| format!("{what} {p}: {e}"))?)
            .metadata()
            .map_err(|e| format!("{what} {p}: {e}"))?;
        let last = std::fs::symlink_metadata(dir).map_err(|e| format!("{what} {p}: {e}"))?;
        if (opened.dev(), opened.ino()) != (last.dev(), last.ino()) {
            return Err(format!("{what} {p}: {} changed while sbx opened it", dir.display()));
        }
        Ok(Destination {
            path: path.to_path_buf(),
            dir_path: dir.to_path_buf(),
            dir: dirfd,
            name: CString::new(name.as_bytes()).map_err(|_| format!("{what} {p}: NUL byte in the path"))?,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A non-root sbx runs the program as its own uid, which owns the
    /// directory: only Landlock can keep the program out of it.
    pub fn check_sandbox_access(&self, what: &str, p: &Policy) -> Result<(), String> {
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return Ok(());
        }
        let d = &self.dir_path;
        if p.landlock.abi == LandlockAbi::Off || p.covered(d, 'r') || p.covered(d, 'w') {
            return Err(format!(
                "{what} {}: sbx runs as uid {euid}, not root, so the program shares its uid and only Landlock \
                 keeps it out of {}; keep the directory outside every fs rule",
                self.path.display(),
                d.display()
            ));
        }
        Ok(())
    }

    /// Remove a file left at the path, e.g. by an earlier run, so that a
    /// report found there always comes from the last run that finished.
    pub fn remove_stale(&self) -> Result<(), String> {
        // SAFETY: unlinkat relative to our directory fd.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) } != 0 && errno() != libc::ENOENT {
            return Err(os_err(format!("removing the old {}", self.path.display())));
        }
        Ok(())
    }

    /// Replace the file with `contents` atomically: a temporary file in the
    /// same directory, fsync, rename over the target, fsync the directory.
    pub fn write_atomic(&self, contents: &[u8]) -> Result<(), String> {
        let p = self.path.display();
        // SAFETY: getpid has no preconditions.
        let tmp = format!(".{}.{}.tmp", self.name.to_string_lossy(), unsafe { libc::getpid() });
        let ctmp = CString::new(tmp.as_bytes()).map_err(|_| format!("{p}: NUL byte in the path"))?;
        // A leftover from an sbx that was killed with the same pid.
        // SAFETY: unlinkat relative to our directory fd.
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), ctmp.as_ptr(), 0) };
        let mut f = self.create(&ctmp, libc::O_EXCL)?;
        let written = f
            .write_all(contents)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("writing {p}: {e}"));
        drop(f);
        // SAFETY: renameat within our directory fd.
        if written.is_err()
            || unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    ctmp.as_ptr(),
                    self.dir.as_raw_fd(),
                    self.name.as_ptr(),
                )
            } != 0
        {
            let e = written
                .err()
                .unwrap_or_else(|| os_err(format!("renaming {tmp} to {p}")));
            // SAFETY: unlinkat relative to our directory fd.
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), ctmp.as_ptr(), 0) };
            return Err(e);
        }
        // SAFETY: fsync on our directory fd.
        if unsafe { libc::fsync(self.dir.as_raw_fd()) } != 0 {
            return Err(os_err(format!("fsync of {}", self.dir_path.display())));
        }
        Ok(())
    }

    /// The log file: appended to, created 0600 if missing. An existing file
    /// must be a regular file of sbx's uid that nobody else can access.
    pub fn open_append(&self) -> Result<File, String> {
        let f = match self.openat(&self.name, libc::O_APPEND | libc::O_CREAT | libc::O_EXCL) {
            Ok(f) => restrict(f, &self.path)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => self
                .openat(&self.name, libc::O_APPEND)
                .map_err(|e| format!("opening {}: {e}", self.path.display()))?,
            Err(e) => return Err(format!("creating {}: {e}", self.path.display())),
        };
        let m = f.metadata().map_err(|e| format!("{}: {e}", self.path.display()))?;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if !m.file_type().is_file() || m.uid() != euid || m.mode() & 0o077 != 0 || m.nlink() != 1 {
            return Err(format!(
                "{} must be a regular file of uid {euid} with mode 0600 and no other links \
                 (it is uid {}, mode {:o}, {} links)",
                self.path.display(),
                m.uid(),
                m.mode() & 0o7777,
                m.nlink()
            ));
        }
        Ok(f)
    }

    /// For `sbx probe`: create and remove a file next to the destination.
    pub fn trial(&self) -> Result<String, String> {
        let name = format!(".{}.probe.{}", self.name.to_string_lossy(), std::process::id());
        let cname = CString::new(name).map_err(|_| "NUL byte in the path".to_string())?;
        drop(self.create(&cname, libc::O_EXCL)?);
        // SAFETY: unlinkat relative to our directory fd.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
            return Err(os_err(format!(
                "removing the probe file in {}",
                self.dir_path.display()
            )));
        }
        Ok(format!("sbx can write {}", self.path.display()))
    }

    /// A new file of mode 0600, whatever the umask.
    fn create(&self, name: &CString, flags: libc::c_int) -> Result<File, String> {
        let f = self.openat(name, flags | libc::O_CREAT).map_err(|e| {
            format!(
                "creating {}: {e}",
                self.dir_path.join(name.to_string_lossy().as_ref()).display()
            )
        })?;
        restrict(f, &self.path)
    }

    fn openat(&self, name: &CString, flags: libc::c_int) -> std::io::Result<File> {
        let flags = flags | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        // SAFETY: openat relative to our directory fd; the fd is owned below.
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a new descriptor we own.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}

/// Mode 0600 for a file sbx just created, whatever the umask.
fn restrict(f: File, path: &Path) -> Result<File, String> {
    // SAFETY: fchmod on our fd.
    if unsafe { libc::fchmod(f.as_raw_fd(), 0o600) } != 0 {
        return Err(os_err(format!("chmod 0600 {}", path.display())));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const EUID: u32 = 1000;

    fn meta() -> impl Strategy<Value = DirMeta> {
        (prop_oneof![Just(0u32), Just(EUID), Just(65534)], 0u32..0o10000).prop_map(|(uid, perm)| DirMeta {
            uid,
            mode: libc::S_IFDIR | perm,
        })
    }

    fn chain(ms: &[DirMeta]) -> Vec<(PathBuf, DirMeta)> {
        ms.iter()
            .enumerate()
            .map(|(i, m)| (PathBuf::from(format!("/d{i}")), *m))
            .collect()
    }

    proptest! {
        /// Nobody but root and sbx's uid can rename, replace or write into
        /// any directory of an accepted chain.
        #[test]
        fn accepted_chains_are_closed_to_others(ms in prop::collection::vec(meta(), 1..6)) {
            let ok = check_chain(&chain(&ms), EUID).is_ok();
            let trusted = |m: &DirMeta| m.uid == 0 || m.uid == EUID;
            let closed = ms.iter().all(trusted)
                && ms.iter().enumerate().all(|(i, m)| {
                    m.mode & 0o022 == 0 || (m.mode & libc::S_ISVTX != 0 && i + 1 < ms.len())
                });
            prop_assert_eq!(ok, closed);
        }
    }

    #[test]
    fn the_files_own_directory_may_not_be_sticky_and_shared() {
        let tmp = DirMeta {
            uid: 0,
            mode: libc::S_IFDIR | 0o1777,
        };
        let root = DirMeta {
            uid: 0,
            mode: libc::S_IFDIR | 0o755,
        };
        assert!(check_chain(&chain(&[root, tmp]), EUID).is_err());
        assert!(check_chain(&chain(&[root, tmp, root]), EUID).is_ok());
    }
}
