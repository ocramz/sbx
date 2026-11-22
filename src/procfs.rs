//! Parsing the /proc files sbx reads about other processes.
//!
//! A process name (comm) can hold any byte but NUL, and the sandbox chooses
//! its own (`PR_SET_NAME`). /proc/<pid>/stat prints it as is, between
//! parentheses, and /proc/<pid>/status escapes only `\n` and `\\` in its
//! `Name:` line. Neither file need be UTF-8, so both are read as bytes and
//! only the fields sbx uses, which are ASCII, are decoded.

/// The fields of /proc/<pid>/stat that sbx uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ppid: libc::pid_t,
    /// State `Z`: exited, not yet reaped.
    pub zombie: bool,
}

impl Stat {
    /// `pid (comm) state ppid ...`: comm may hold anything, `)` and spaces
    /// included, so the fields start after the last `)`.
    pub fn parse(stat: &[u8]) -> Option<Stat> {
        let close = stat.iter().rposition(|&b| b == b')')?;
        let rest = std::str::from_utf8(&stat[close + 1..]).ok()?;
        let mut f = rest.split_ascii_whitespace();
        let state = f.next()?;
        let ppid = f.next()?.parse().ok()?;
        Some(Stat {
            ppid,
            zombie: state == "Z",
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
    pub fn stat(pid: libc::pid_t, name: &[u8], state: char, ppid: libc::pid_t) -> Vec<u8> {
        let mut out = format!("{pid} (").into_bytes();
        out.extend_from_slice(name);
        out.extend_from_slice(
            format!(") {state} {ppid} {pid} {pid} 0 -1 4194560 120 0 0 0 1 2 0 0 20 0 1 0 987654 ").as_bytes(),
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
        ) {
            let got = Stat::parse(&render::stat(pid, &name, state, ppid));
            prop_assert_eq!(got, Some(Stat { ppid, zombie: state == 'Z' }));
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
    fn a_name_cannot_forge_a_status_line() {
        let s = render::status(b"x\nUid:\t0\t0\t0\t0", &[("Uid:", "65534\t65534\t65534\t65534".into())]);
        assert_eq!(status_text(&s, "Uid:"), Some("65534\t65534\t65534\t65534"));
    }
}
