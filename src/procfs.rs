//! Parsing the /proc files sbx reads about other processes.
//!
//! A process name (comm) can hold any byte but NUL, and the sandbox chooses
//! its own (`PR_SET_NAME`). /proc/<pid>/stat prints it as is, between
//! parentheses, and /proc/<pid>/status escapes only `\n` and `\\` in its
//! `Name:` line. Neither file need be UTF-8, so both are read as bytes and
//! only the fields sbx uses, which are ASCII, are decoded.

/// When a process started, in clock ticks since boot (field 22 of
/// /proc/<pid>/stat). With the pid it names one process: a recycled pid
/// belongs to a process that started later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StartTicks(pub u64);

/// A process name as the kernel keeps it: at most 16 bytes (TASK_COMM_LEN),
/// any but NUL.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Comm {
    bytes: [u8; Comm::LEN],
    len: u8,
}

impl Comm {
    pub const LEN: usize = 16;

    /// `name`, cut to [`Comm::LEN`] bytes: only a kernel thread's can be longer.
    pub fn new(name: &[u8]) -> Comm {
        let len = name.len().min(Comm::LEN);
        let mut bytes = [0; Comm::LEN];
        bytes[..len].copy_from_slice(&name[..len]);
        Comm { bytes, len: len as u8 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl std::fmt::Debug for Comm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Comm({:?})", self.as_bytes().escape_ascii().to_string())
    }
}

/// The fields of /proc/<pid>/stat that sbx uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ppid: libc::pid_t,
    /// State `Z`: exited, not yet reaped.
    pub zombie: bool,
    pub start_ticks: StartTicks,
    pub comm: Comm,
}

impl Stat {
    /// `pid (comm) state ppid ...`: comm may hold anything, `)` and spaces
    /// included, so the fields start after the last `)`.
    pub fn parse(stat: &[u8]) -> Option<Stat> {
        let open = stat.iter().position(|&b| b == b'(')?;
        let close = stat.iter().rposition(|&b| b == b')')?;
        let comm = Comm::new(stat.get(open + 1..close)?);
        let rest = std::str::from_utf8(&stat[close + 1..]).ok()?;
        let f: Vec<&str> = rest.split_ascii_whitespace().collect();
        // Field 3 (state) is f[0], so field 22 (starttime) is f[19].
        Some(Stat {
            ppid: f.get(1)?.parse().ok()?,
            zombie: *f.first()? == "Z",
            start_ticks: StartTicks(f.get(19)?.parse().ok()?),
            comm,
        })
    }
}

/// The value of the first line of /proc/<pid>/status that starts with
/// `name` (such as `"Tgid:"`), without the blanks around it. The kernel
/// escapes `\n` in the process name, so the name cannot add lines.
pub fn status_field<'a>(status: &'a [u8], name: &str) -> Option<&'a [u8]> {
    status
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(name.as_bytes()))
        .map(<[u8]>::trim_ascii)
}

/// [`status_field`] when it is text: every field but `Name:` is ASCII.
pub fn status_text<'a>(status: &'a [u8], name: &str) -> Option<&'a str> {
    std::str::from_utf8(status_field(status, name)?).ok()
}

/// How the kernel prints a process name, and test renderings of the files.
#[cfg(test)]
pub mod render {
    /// The `Name:` line's escaping (fs/proc/array.c, `proc_task_name`):
    /// only `\n` and `\\`, as `\n` and `\\`.
    pub fn status_name(name: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(name.len());
        for &b in name {
            match b {
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\\' => out.extend_from_slice(b"\\\\"),
                _ => out.push(b),
            }
        }
        out
    }

    /// /proc/<pid>/status with `name` and the given lines after it.
    pub fn status(name: &[u8], lines: &[(&str, String)]) -> Vec<u8> {
        let mut out = b"Name:\t".to_vec();
        out.extend(status_name(name));
        out.push(b'\n');
        for (k, v) in lines {
            out.extend_from_slice(format!("{k}\t{v}\n").as_bytes());
        }
        out
    }

    /// /proc/<pid>/stat: the name as is.
    pub fn stat(pid: libc::pid_t, name: &[u8], state: char, ppid: libc::pid_t, start: u64) -> Vec<u8> {
        let mut out = format!("{pid} (").into_bytes();
        out.extend_from_slice(name);
        out.extend_from_slice(
            format!(") {state} {ppid} {pid} {pid} 0 -1 4194560 120 0 0 0 1 2 0 0 20 0 1 0 {start} ").as_bytes(),
        );
        out.extend_from_slice(b"12345678 300 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Any name the kernel accepts: up to 15 bytes, anything but NUL.
    fn name() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(
            prop_oneof![1..=255u8, Just(b')'), Just(b'('), Just(b' '), Just(b'\n')],
            0..16,
        )
    }

    proptest! {
        #[test]
        fn stat_parsing_finds_the_fields_whatever_the_name(
            pid in 1..libc::pid_t::MAX,
            name in name(),
            state in prop::sample::select(vec!['R', 'S', 'D', 'Z', 'T', 't', 'X', 'I']),
            ppid in 0..libc::pid_t::MAX,
            start in any::<u64>(),
        ) {
            let got = Stat::parse(&render::stat(pid, &name, state, ppid, start));
            let want = Stat { ppid, zombie: state == 'Z', start_ticks: StartTicks(start), comm: Comm::new(&name) };
            prop_assert_eq!(got, Some(want));
        }

        #[test]
        fn status_fields_are_found_whatever_the_name(
            name in name(),
            tgid in 1..libc::pid_t::MAX,
            uids in [any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()],
            anon in any::<u64>(),
        ) {
            let uid_line = uids.map(|u| u.to_string()).join("\t");
            let s = render::status(&name, &[
                ("Umask:", "0022".into()),
                ("State:", "S (sleeping)".into()),
                ("Tgid:", tgid.to_string()),
                ("Uid:", uid_line.clone()),
                ("RssAnon:", format!("{anon:>8} kB")),
            ]);
            let (escaped, tgid, anon) = (render::status_name(&name), tgid.to_string(), format!("{anon} kB"));
            prop_assert_eq!(status_field(&s, "Name:"), Some(escaped.trim_ascii()));
            prop_assert_eq!(status_text(&s, "Tgid:"), Some(tgid.as_str()));
            prop_assert_eq!(status_text(&s, "Uid:"), Some(uid_line.as_str()));
            prop_assert_eq!(status_text(&s, "RssAnon:"), Some(anon.as_str()));
            prop_assert_eq!(status_text(&s, "VmSwap:"), None);
        }
    }

    #[test]
    fn a_stat_line_without_the_start_time_is_not_parsed() {
        let full = render::stat(7, b"sh", 'S', 1, 42);
        let cut = full.split(|&b| b == b' ').take(21).collect::<Vec<_>>().join(&b' ');
        assert_eq!(Stat::parse(&cut), None);
        assert_eq!(Stat::parse(b"7 sh S 1"), None);
    }

    #[test]
    fn a_name_cannot_forge_a_status_line() {
        let s = render::status(b"x\nUid:\t0\t0\t0\t0", &[("Uid:", "65534\t65534\t65534\t65534".into())]);
        assert_eq!(status_text(&s, "Uid:"), Some("65534\t65534\t65534\t65534"));
    }
}
