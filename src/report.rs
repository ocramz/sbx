//! The outcome of `sbx run`, for the exit code, the log and the JSON report
//! (`--report FILE`). The report is written once, after the sandbox is torn
//! down, by the supervisor; see [`crate::destination`] for where it may go.

use crate::cgroup::CgroupStats;
use serde::Serialize;

/// Where `sbx run` failed before the program started: a step of the
/// supervisor's preparation, or of the child's setup before `execve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    // The supervisor, before fork.
    Policy,
    Report,
    Log,
    Env,
    Program,
    Capabilities,
    Slot,
    Stdio,
    Dns,
    Cgroup,
    Landlock,
    Seccomp,
    Launch,
    // The child, between fork and execve (Cgroup, Landlock and Seccomp too).
    Setsid,
    Chdir,
    Setrlimit,
    Identity,
    Pdeathsig,
    NoNewPrivs,
    CloseRange,
    Signals,
    Execve,
    // The supervisor, after fork.
    Listener,
    Services,
}

impl Stage {
    pub const ALL: [Stage; 24] = [
        Stage::Policy,
        Stage::Report,
        Stage::Log,
        Stage::Env,
        Stage::Program,
        Stage::Capabilities,
        Stage::Slot,
        Stage::Stdio,
        Stage::Dns,
        Stage::Cgroup,
        Stage::Landlock,
        Stage::Seccomp,
        Stage::Launch,
        Stage::Setsid,
        Stage::Chdir,
        Stage::Setrlimit,
        Stage::Identity,
        Stage::Pdeathsig,
        Stage::NoNewPrivs,
        Stage::CloseRange,
        Stage::Signals,
        Stage::Execve,
        Stage::Listener,
        Stage::Services,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Policy => "policy",
            Stage::Report => "report",
            Stage::Log => "log",
            Stage::Env => "env",
            Stage::Program => "program",
            Stage::Capabilities => "capabilities",
            Stage::Slot => "slot",
            Stage::Stdio => "stdio",
            Stage::Dns => "dns",
            Stage::Cgroup => "cgroup",
            Stage::Landlock => "landlock",
            Stage::Seccomp => "seccomp",
            Stage::Launch => "launch",
            Stage::Setsid => "setsid",
            Stage::Chdir => "chdir",
            Stage::Setrlimit => "setrlimit",
            Stage::Identity => "identity",
            Stage::Pdeathsig => "pdeathsig",
            Stage::NoNewPrivs => "no_new_privs",
            Stage::CloseRange => "close_range",
            Stage::Signals => "signals",
            Stage::Execve => "execve",
            Stage::Listener => "listener",
            Stage::Services => "services",
        }
    }

    /// Split a child's `"stage: message"` setup report.
    pub fn from_prefix(msg: &str) -> Option<(Stage, &str)> {
        let (name, rest) = msg.split_once(": ")?;
        Stage::ALL.into_iter().find(|s| s.as_str() == name).map(|s| (s, rest))
    }

    /// sbx's exit code when setup fails here.
    pub fn exit_code(self) -> i32 {
        match self {
            Stage::Execve => 127,
            _ => 125,
        }
    }
}

/// Every error of one failed setup stage.
#[derive(Debug)]
pub struct SetupError {
    pub stage: Stage,
    pub errors: Vec<String>,
}

/// Attach the stage to a setup step's error.
pub trait At<T> {
    fn at(self, stage: Stage) -> Result<T, SetupError>;
}

impl<T> At<T> for Result<T, String> {
    fn at(self, stage: Stage) -> Result<T, SetupError> {
        self.map_err(|e| SetupError { stage, errors: vec![e] })
    }
}

impl<T> At<T> for Result<T, Vec<String>> {
    fn at(self, stage: Stage) -> Result<T, SetupError> {
        self.map_err(|errors| SetupError { stage, errors })
    }
}

/// How the program's own process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Program {
    Exited(i32),
    Signaled(i32),
}

impl Program {
    /// From a waitpid status (sbx never asks for stopped or continued children).
    pub fn from_wait_status(st: libc::c_int) -> Option<Program> {
        if libc::WIFEXITED(st) {
            Some(Program::Exited(libc::WEXITSTATUS(st)))
        } else if libc::WIFSIGNALED(st) {
            Some(Program::Signaled(libc::WTERMSIG(st)))
        } else {
            None
        }
    }
}

/// sbx's exit code once the program ran: 125 when sbx failed (`fatal`),
/// 124 on timeout, the program's code, or 128+N when signal N killed it.
pub fn exit_code(fatal: bool, timed_out: bool, program: Option<Program>) -> i32 {
    match (fatal, timed_out, program) {
        (true, _, _) => 125,
        (false, true, _) => 124,
        (false, false, Some(Program::Exited(n))) => n,
        (false, false, Some(Program::Signaled(s))) => 128 + s,
        (false, false, None) => 125,
    }
}

/// CPU time and peak memory of the processes sbx reaped (each one includes
/// the descendants it waited for itself).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub user_us: u64,
    pub sys_us: u64,
    /// The largest resident set of any single process, not of the tree.
    pub max_rss_kib: u64,
}

impl Usage {
    pub fn from_rusage(ru: &libc::rusage) -> Usage {
        let us = |t: libc::timeval| (t.tv_sec.max(0) as u64) * 1_000_000 + t.tv_usec.max(0) as u64;
        Usage {
            user_us: us(ru.ru_utime),
            sys_us: us(ru.ru_stime),
            max_rss_kib: ru.ru_maxrss.max(0) as u64,
        }
    }

    pub fn combine(self, o: Usage) -> Usage {
        Usage {
            user_us: self.user_us.saturating_add(o.user_us),
            sys_us: self.sys_us.saturating_add(o.sys_us),
            max_rss_kib: self.max_rss_kib.max(o.max_rss_kib),
        }
    }
}

/// The program started: everything the supervisor saw until teardown.
#[derive(Debug)]
pub struct Ran {
    pub exit_code: i32,
    pub program: Option<Program>,
    pub timed_out: bool,
    pub supervisor_error: Option<String>,
    /// Syscalls the policy filter denied, per name.
    pub denials: Vec<(String, u64)>,
    /// Processes still running when the program exited, which sbx then
    /// killed; None when sbx had already killed the tree (timeout, signals,
    /// fatal error).
    pub killed_after_exit: Option<u32>,
    /// From execve until the program's process was reaped.
    pub wall_ms: u64,
    pub usage: Usage,
    pub cgroup: Option<CgroupStats>,
}

#[derive(Debug)]
pub enum Outcome {
    SetupFailed(SetupError),
    Ran(Ran),
}

impl Outcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::SetupFailed(e) => e.stage.exit_code(),
            Outcome::Ran(r) => r.exit_code,
        }
    }

    /// The report: every key is always present, null where it does not apply.
    pub fn to_json(&self, sbx_version: &str) -> Result<Vec<u8>, String> {
        let mut r = Json {
            sbx_version,
            exit_code: self.exit_code(),
            program: None,
            timed_out: false,
            setup_error: None,
            supervisor_error: None,
            denials: vec![],
            killed_after_exit: None,
            wall_ms: None,
            rusage: None,
            cgroup: None,
        };
        match self {
            Outcome::SetupFailed(e) => {
                r.setup_error = Some(JsonSetupError {
                    stage: e.stage,
                    messages: &e.errors,
                })
            }
            Outcome::Ran(ran) => {
                r.program = ran.program;
                r.timed_out = ran.timed_out;
                r.supervisor_error = ran.supervisor_error.as_deref();
                r.denials = ran
                    .denials
                    .iter()
                    .map(|(syscall, count)| JsonDenial { syscall, count: *count })
                    .collect();
                r.killed_after_exit = ran.killed_after_exit;
                r.wall_ms = Some(ran.wall_ms);
                r.rusage = Some(JsonUsage {
                    user_ms: ran.usage.user_us / 1000,
                    sys_ms: ran.usage.sys_us / 1000,
                    max_rss_kib: ran.usage.max_rss_kib,
                });
                r.cgroup = ran.cgroup.as_ref();
            }
        }
        let mut out = serde_json::to_vec_pretty(&r).map_err(|e| format!("serializing the report: {e}"))?;
        out.push(b'\n');
        Ok(out)
    }
}

#[derive(Serialize)]
struct Json<'a> {
    sbx_version: &'a str,
    exit_code: i32,
    program: Option<Program>,
    timed_out: bool,
    setup_error: Option<JsonSetupError<'a>>,
    supervisor_error: Option<&'a str>,
    denials: Vec<JsonDenial<'a>>,
    killed_after_exit: Option<u32>,
    wall_ms: Option<u64>,
    rusage: Option<JsonUsage>,
    cgroup: Option<&'a CgroupStats>,
}

#[derive(Serialize)]
struct JsonSetupError<'a> {
    stage: Stage,
    messages: &'a [String],
}

#[derive(Serialize)]
struct JsonDenial<'a> {
    syscall: &'a str,
    count: u64,
}

#[derive(Serialize)]
struct JsonUsage {
    user_ms: u64,
    sys_ms: u64,
    max_rss_kib: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn every_stage_round_trips_through_the_child_pipe_format() {
        for s in Stage::ALL {
            let msg = format!("{}: /bin/x: Permission denied", s.as_str());
            assert_eq!(Stage::from_prefix(&msg), Some((s, "/bin/x: Permission denied")));
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
        assert_eq!(Stage::from_prefix("nonsense: x"), None);
        assert_eq!(Stage::from_prefix("execve"), None);
    }

    #[test]
    fn only_a_failed_execve_exits_127() {
        for s in Stage::ALL {
            assert_eq!(s.exit_code(), if s == Stage::Execve { 127 } else { 125 }, "{s:?}");
        }
    }

    fn usage() -> impl Strategy<Value = Usage> {
        (0..u64::MAX / 4, 0..u64::MAX / 4, any::<u64>()).prop_map(|(user_us, sys_us, max_rss_kib)| Usage {
            user_us,
            sys_us,
            max_rss_kib,
        })
    }

    fn program() -> impl Strategy<Value = Option<Program>> {
        prop_oneof![
            Just(None),
            (0..=255).prop_map(|n| Some(Program::Exited(n))),
            (1..=64).prop_map(|s| Some(Program::Signaled(s))),
        ]
    }

    proptest! {
        #[test]
        fn usage_adds_times_and_keeps_the_largest_process(a in usage(), b in usage(), c in usage()) {
            prop_assert_eq!(a.combine(b), b.combine(a));
            prop_assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
            prop_assert_eq!(a.combine(Usage::default()), a);
            let ab = a.combine(b);
            prop_assert_eq!(ab.user_us, a.user_us + b.user_us);
            prop_assert_eq!(ab.max_rss_kib, a.max_rss_kib.max(b.max_rss_kib));
        }

        #[test]
        fn exit_codes_follow_the_documented_precedence(fatal: bool, timed_out: bool, p in program()) {
            let code = exit_code(fatal, timed_out, p);
            let want = if fatal {
                125
            } else if timed_out {
                124
            } else {
                match p {
                    Some(Program::Exited(n)) => n,
                    Some(Program::Signaled(s)) => 128 + s,
                    None => 125,
                }
            };
            prop_assert_eq!(code, want);
        }

        #[test]
        fn wait_statuses_map_to_exit_or_signal(code in 0..=255i32, sig in 1..=64i32) {
            prop_assert_eq!(Program::from_wait_status(code << 8), Some(Program::Exited(code)));
            prop_assert_eq!(Program::from_wait_status(sig), Some(Program::Signaled(sig)));
        }
    }

    #[test]
    fn report_keys_are_always_present() {
        let failed = Outcome::SetupFailed(SetupError {
            stage: Stage::Execve,
            errors: vec!["x".into()],
        });
        let v: serde_json::Value = serde_json::from_slice(&failed.to_json("v0.3").unwrap()).unwrap();
        assert_eq!(v["exit_code"], 127);
        assert_eq!(v["setup_error"]["stage"], "execve");
        assert!(v["program"].is_null() && v["wall_ms"].is_null() && v["cgroup"].is_null());

        let ran = Outcome::Ran(Ran {
            exit_code: 137,
            program: Some(Program::Signaled(9)),
            timed_out: false,
            supervisor_error: None,
            denials: vec![("ptrace".into(), 2)],
            killed_after_exit: Some(1),
            wall_ms: 5,
            usage: Usage {
                user_us: 2500,
                sys_us: 999,
                max_rss_kib: 7,
            },
            cgroup: None,
        });
        let v: serde_json::Value = serde_json::from_slice(&ran.to_json("v0.3").unwrap()).unwrap();
        assert_eq!(v["program"]["signaled"], 9);
        assert_eq!(v["denials"][0]["syscall"], "ptrace");
        assert_eq!(v["rusage"]["user_ms"], 2);
        assert!(v["setup_error"].is_null());
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 11, "{keys:?}");
    }
}
