//! Logging. Every line is prefixed with `sbx:` and a level so the
//! supervisor's output is easy to tell apart from the sandboxed program's.
//! Lines go to stderr, or to the file given with `--log` / `SBX_LOG_FILE`,
//! which keeps them off the program's stderr altogether. `--quiet` /
//! `SBX_QUIET=true` hides `info` lines; errors and warnings are always
//! written.
//!
//! Text the sandbox controls (process names, DNS names) goes through
//! [`untrusted`] so it cannot start a line of its own.

use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static QUIET: AtomicBool = AtomicBool::new(false);
static SINK: OnceLock<File> = OnceLock::new();
static FATAL: OnceLock<String> = OnceLock::new();

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Send every later line to `f` instead of stderr.
pub fn set_file(f: File) -> Result<(), String> {
    SINK.set(f).map_err(|_| "BUG: the log file is set twice".to_string())
}

pub fn error(msg: impl Display) {
    emit("error", msg);
}

pub fn warn(msg: impl Display) {
    emit("warning", msg);
}

pub fn info(msg: impl Display) {
    if !QUIET.load(Ordering::Relaxed) {
        emit("info", msg);
    }
}

/// One write per line: the notification, egress and DNS threads log
/// concurrently, and `eprintln!` may split a line into several writes.
fn emit(level: &str, msg: impl Display) {
    let line = format!("sbx: {level}: {msg}\n");
    let Some(mut f) = SINK.get() else {
        let _ = std::io::stderr().write_all(line.as_bytes());
        return;
    };
    if let Err(e) = f.write_all(line.as_bytes()) {
        // Not through the sink again: report on stderr and stop the sandbox,
        // since sbx can no longer log what the operator asked for.
        let _ = std::io::stderr().write_all(format!("sbx: error: writing the log file: {e}\n{line}").as_bytes());
        fatal(format!("writing the log file: {e}"));
    }
}

/// Signal the dispatcher, the DNS proxy and the log sink raise on the
/// supervisor when they fail; the main loop then tears the sandbox down
/// (exit 125).
pub fn fatal_signal() -> libc::c_int {
    libc::SIGRTMIN() + 1
}

/// Log `what` and tear the sandbox down.
pub fn raise_fatal(what: &str) {
    error(format!("{what}; terminating the sandbox"));
    fatal(what.to_string());
}

fn fatal(what: String) {
    let _ = FATAL.set(what);
    // SAFETY: plain signal to our own process.
    unsafe { libc::kill(libc::getpid(), fatal_signal()) };
}

/// The first failure that tore the sandbox down, if any.
pub fn fatal_message() -> Option<String> {
    FATAL.get().cloned()
}

/// `s` with every control character escaped (`\n` becomes `\\n`), so text
/// from the sandbox cannot forge log lines.
pub fn untrusted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// `what: <strerror(errno)>` for the calling thread's last OS error.
pub fn os_err(what: impl Display) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Last OS error number of the calling thread.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn untrusted_text_never_contains_control_characters(s in any::<String>()) {
            prop_assert!(!untrusted(&s).chars().any(char::is_control));
        }

        #[test]
        fn untrusted_leaves_text_without_control_characters_alone(s in "[^\\p{Cc}]*") {
            prop_assert_eq!(untrusted(&s), s);
        }
    }

    #[test]
    fn a_newline_cannot_start_a_forged_line() {
        assert_eq!(untrusted("x\nsbx: info: allowed"), "x\\nsbx: info: allowed");
    }
}
