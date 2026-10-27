//! Logging to stderr. Every line is prefixed with `sbx:` and a level so the
//! supervisor's output is easy to tell apart from the sandboxed program's.
//! `--quiet` / `SBX_QUIET=true` hides `info` lines; errors and warnings are
//! always printed.

use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};

static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn error(msg: impl Display) {
    eprintln!("sbx: error: {msg}");
}

pub fn warn(msg: impl Display) {
    eprintln!("sbx: warning: {msg}");
}

pub fn info(msg: impl Display) {
    if !QUIET.load(Ordering::Relaxed) {
        eprintln!("sbx: info: {msg}");
    }
}

/// `what: <strerror(errno)>` for the calling thread's last OS error.
pub fn os_err(what: impl Display) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Last OS error number of the calling thread.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
