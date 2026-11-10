//! `/proc/<pid>/stat` fixtures (m03-plan U11 `procstat::Fixtures`; ADR-0008 D5 §6.3
//! "The shared parser", §17.13 item 2; M03-R5-02). Feature `fixtures`.
//!
//! * [`Fixtures::synthetic`]: whole `/proc/<pid>/stat` texts whose `comm` is `plain`,
//!   `has space`, `a ) b ( c`, `)(`, a 15-byte name and a name with a newline, each
//!   with its expected parse; and the malformed texts (no `)`, fewer than 20 suffix
//!   tokens, a non-decimal or zero process group, a non-decimal start time, a bad
//!   state), each with its expected rejection. The expectations are
//!   [`heimdall_domain::procstat`]'s types, so U5's agreement test
//!   (`procstat_fixtures_rust_and_awk_agree`) compares the scripts' `awk` text and the
//!   Rust parser against the same values.
//! * [`Fixtures::committed`]: wave 0's committed synthetic set
//!   (`tests/fixtures/procstat/*.stat` with `golden.json`; U0b row 28), read through
//!   `repo::repo_root`, with its expectations, so both sets go through the same checks.
//! * [`LiveComm::spawn_in_container`]: live processes inside a Linux container (U11's
//!   shell containers, or the M00-T03 Debian target) whose `comm` is set to those
//!   names, each leading its own process group, with expected values read
//!   **independently**: each process first records its own `/proc/$$/stat` while its
//!   `comm` is still the plain `sh` (where a whitespace split is valid), then `exec`s a
//!   renamed copy of a scratch script whose file name is the wanted `comm` (an `exec`
//!   keeps the PID, the group and the start time; the kernel takes `comm` from the
//!   script's file name, truncated to 15 bytes).

use std::io;
use std::time::{Duration, Instant};

use heimdall_domain::procstat::{ProcStat, ProcStatError};

use crate::agent::random_hex;
use crate::registry::{docker_exec_run, is_container_name};

/// The `comm` names every fixture covers (ADR-0008 D5 §6.3; m03-plan U11).
pub const COMM_NAMES: [&[u8]; 6] = [
    b"plain",
    b"has space",
    b"a ) b ( c",
    b")(",
    b"fifteen-bytes-x",
    b"new\nline",
];

/// The kernel's `comm` limit (`TASK_COMM_LEN - 1`).
pub const COMM_MAX: usize = 15;

/// One synthetic `/proc/<pid>/stat` text and what the shared parser must make of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticStat {
    /// A short label (`comm:has space`, `malformed:no_close_paren`, …).
    pub label: String,
    /// The whole file text, ending in a newline as the kernel writes it.
    pub text: Vec<u8>,
    /// The expected parse.
    pub expected: Result<ProcStat, ProcStatError>,
}

/// One committed fixture file (`tests/fixtures/procstat/<file>`) and its golden
/// expectation: the parse, or the rejection's code ([`error_code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedStat {
    /// The file name.
    pub file: String,
    /// The file's bytes.
    pub text: Vec<u8>,
    /// The golden parse, or the golden error code.
    pub expected: Result<ProcStat, String>,
}

/// The golden code of a rejection (`no_close_paren`, `too_few_fields`, `bad_state`,
/// `bad_process_group`, `bad_start_time`), as `tests/fixtures/procstat/golden.json`
/// spells it.
#[must_use]
pub fn error_code(e: &ProcStatError) -> &'static str {
    match e {
        ProcStatError::NoCloseParen => "no_close_paren",
        ProcStatError::TooFewFields { .. } => "too_few_fields",
        ProcStatError::BadState => "bad_state",
        ProcStatError::BadProcessGroup => "bad_process_group",
        ProcStatError::BadStartTime => "bad_start_time",
        _ => "unknown",
    }
}

/// The fixture sets.
#[derive(Debug, Clone, Copy)]
pub struct Fixtures;

/// A realistic stat text: `pid (comm) state ppid pgrp session …` with the start time as
/// token 20 after the last `)`, and 52 fields in all (the field count of Linux 6.x).
fn stat_text(pid: u32, comm: &[u8], state: &str, pgrp: &str, start: &str) -> Vec<u8> {
    let mut text = format!("{pid} (").into_bytes();
    text.extend_from_slice(comm);
    text.extend_from_slice(
        format!(
            ") {state} 1 {pgrp} {pid} 0 -1 4194560 197 191 0 0 0 0 0 0 20 0 1 0 {start} \
             4005888 697 18446744073709551615 187650751791104 187650753105712 \
             281474315174880 0 0 0 65536 4 65538 1 0 0 17 8 0 0 0 0 0 187650753215216 \
             187650753266620 187651220566016 281474315177769 281474315177869 \
             281474315177869 281474315177968 0\n"
        )
        .as_bytes(),
    );
    text
}

impl Fixtures {
    /// Every synthetic text: one valid text per [`COMM_NAMES`] entry (group = PID, a
    /// distinct start time each), then the malformed ones.
    #[must_use]
    pub fn synthetic() -> Vec<SyntheticStat> {
        let mut out = Vec::new();
        for (i, comm) in COMM_NAMES.iter().enumerate() {
            let pid = 4200 + u32::try_from(i).unwrap_or(0);
            let start = 7_438_000 + u64::try_from(i).unwrap_or(0);
            out.push(SyntheticStat {
                label: format!("comm:{}", String::from_utf8_lossy(comm).escape_default()),
                text: stat_text(pid, comm, "S", &pid.to_string(), &start.to_string()),
                expected: Ok(ProcStat {
                    state: 'S',
                    process_group: pid,
                    start_time: start,
                }),
            });
        }
        let mut no_paren =
            b"4300 (plain S 1 4300 4300 0 -1 4194560 197 191 0 0 0 0 0 0 20 0 1 0 55 0\n".to_vec();
        no_paren.retain(|&b| b != b')');
        out.push(SyntheticStat {
            label: "malformed:no_close_paren".to_owned(),
            text: no_paren,
            expected: Err(ProcStatError::NoCloseParen),
        });
        out.push(SyntheticStat {
            label: "malformed:too_few_fields".to_owned(),
            text: b"4301 (plain) S 1 4301 4301 0\n".to_vec(),
            expected: Err(ProcStatError::TooFewFields { found: 5 }),
        });
        for (label, pgrp) in [("non_decimal", "x7"), ("zero", "0"), ("negative", "-7")] {
            out.push(SyntheticStat {
                label: format!("malformed:process_group_{label}"),
                text: stat_text(4302, b"has space", "S", pgrp, "55"),
                expected: Err(ProcStatError::BadProcessGroup),
            });
        }
        out.push(SyntheticStat {
            label: "malformed:start_time_non_decimal".to_owned(),
            text: stat_text(4303, b"a ) b ( c", "S", "4303", "12a"),
            expected: Err(ProcStatError::BadStartTime),
        });
        out.push(SyntheticStat {
            label: "malformed:state_not_one_letter".to_owned(),
            text: stat_text(4304, b")(", "SS", "4304", "55"),
            expected: Err(ProcStatError::BadState),
        });
        out
    }

    /// Wave 0's committed set, read from `tests/fixtures/procstat/` under
    /// [`crate::repo::repo_root`], in `golden.json` order.
    ///
    /// # Errors
    /// A file is missing or `golden.json` is malformed.
    pub fn committed() -> io::Result<Vec<CommittedStat>> {
        let dir = crate::repo::repo_path("tests/fixtures/procstat");
        let golden: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("golden.json"))?)
                .map_err(|_| io::Error::other("golden.json is not JSON"))?;
        let bad = || io::Error::other("golden.json entry is malformed");
        let fixtures = golden
            .get("fixtures")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(bad)?;
        let mut out = Vec::new();
        for (file, want) in fixtures {
            if !file.ends_with(".stat") || file.contains('/') {
                return Err(bad());
            }
            let expected = match want.get("error").and_then(serde_json::Value::as_str) {
                Some(code) => Err(code.to_owned()),
                None => {
                    let state = want
                        .get("state")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.chars().next())
                        .ok_or_else(bad)?;
                    let process_group = want
                        .get("process_group")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|g| u32::try_from(g).ok())
                        .ok_or_else(bad)?;
                    let start_time = want
                        .get("start_time")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(bad)?;
                    Ok(ProcStat {
                        state,
                        process_group,
                        start_time,
                    })
                }
            };
            out.push(CommittedStat {
                file: file.clone(),
                text: std::fs::read(dir.join(file))?,
                expected,
            });
        }
        Ok(out)
    }

    /// `awk '{print $5}'`'s naive reading of a text (the whitespace field count the
    /// shared parser replaces), for showing the difference: `None` past the end.
    #[must_use]
    pub fn naive_field5(text: &[u8]) -> Option<String> {
        text.split(u8::is_ascii_whitespace)
            .filter(|t| !t.is_empty())
            .nth(4)
            .map(|t| String::from_utf8_lossy(t).into_owned())
    }
}

/// One live process whose `comm` is a fixture name (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProc {
    /// The `comm` asked for.
    pub requested: Vec<u8>,
    /// The `comm` the kernel keeps (truncated to [`COMM_MAX`] bytes).
    pub expected_comm: Vec<u8>,
    /// Its PID inside the container.
    pub pid: u32,
    /// Its process group, read before the rename (equal to `pid`: it leads its group).
    pub expected_process_group: u32,
    /// Its start time in clock ticks, read before the rename.
    pub expected_start_time: u64,
}

/// The live `comm` processes of one container; killed by their exact groups, and their
/// scratch directory removed, on drop.
#[derive(Debug)]
pub struct LiveComm {
    container: String,
    user: Option<String>,
    dir: String,
    procs: Vec<LiveProc>,
}

/// Start one renamed process (run inside the container by `/bin/sh -c`): `$1` its
/// directory, `$2` the name. It records its own stat while its `comm` is `sh`, then
/// `exec`s the renamed script, which loops.
const LAUNCH: &str = "mkdir -p \"$1\" && \
    printf '#!/bin/sh\\nwhile :; do sleep 1; done\\n' > \"$1/$2\" && chmod 755 \"$1/$2\" && \
    setsid /bin/sh -c 'cat /proc/$$/stat > \"$1/before.tmp\" && mv \"$1/before.tmp\" \"$1/before\" && exec \"$1/$2\"' sh \"$1\" \"$2\" \
    > /dev/null 2>&1 < /dev/null &";

impl LiveComm {
    /// Start one live process per [`COMM_NAMES`] entry inside `container` (as `user`,
    /// or the container's default account), each in its own session and group, under
    /// `/tmp/hm-comm-<random>`.
    ///
    /// # Errors
    /// A bad container name, `docker exec` failed, or a process did not report in
    /// time.
    pub fn spawn_in_container(container: &str, user: Option<&str>) -> io::Result<LiveComm> {
        if !is_container_name(container) {
            return Err(io::Error::other("bad container name"));
        }
        if user.is_some_and(|u| !u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')) {
            return Err(io::Error::other("bad user"));
        }
        let mut live = LiveComm {
            container: container.to_owned(),
            user: user.map(str::to_owned),
            dir: format!("/tmp/hm-comm-{}", random_hex(6)),
            procs: Vec::new(),
        };
        for (i, name) in COMM_NAMES.iter().enumerate() {
            let name_text = String::from_utf8_lossy(name).into_owned();
            let dir = format!("{}/{i}", live.dir);
            live.run(&["/bin/sh", "-c", LAUNCH, "sh", &dir, &name_text])?;
            let before = live.wait_for_file(&format!("{dir}/before"))?;
            let fields: Vec<&str> = std::str::from_utf8(&before)
                .map_err(|_| io::Error::other("stat is not text"))?
                .split_whitespace()
                .collect();
            // comm is `sh` here, so whitespace fields are the kernel's fields.
            let field = |n: usize| fields.get(n - 1).copied().unwrap_or("");
            let pid: u32 = field(1).parse().map_err(|_| io::Error::other("pid"))?;
            let group: u32 = field(5).parse().map_err(|_| io::Error::other("pgrp"))?;
            let start: u64 = field(22).parse().map_err(|_| io::Error::other("start"))?;
            if field(2) != "(sh)" || group != pid {
                return Err(io::Error::other(
                    "the live process does not lead its own group",
                ));
            }
            let expected_comm = name[..name.len().min(COMM_MAX)].to_vec();
            live.procs.push(LiveProc {
                requested: name.to_vec(),
                expected_comm: expected_comm.clone(),
                pid,
                expected_process_group: group,
                expected_start_time: start,
            });
            live.wait_for_comm(pid, &expected_comm)?;
        }
        Ok(live)
    }

    fn run(&self, args: &[&str]) -> io::Result<Vec<u8>> {
        let child = crate::registry::docker_exec_spawn(
            &self.container,
            args,
            false,
            self.user.as_deref(),
            &[],
        )?;
        let run = crate::registry::finish(child, None, Duration::from_secs(60))?;
        if run.status == Some(0) {
            Ok(run.stdout)
        } else {
            Err(io::Error::other("docker exec failed"))
        }
    }

    fn wait_for_file(&self, path: &str) -> io::Result<Vec<u8>> {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(bytes) = self.run(&["cat", path])
                && !bytes.is_empty()
            {
                return Ok(bytes);
            }
            if Instant::now() >= end {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "a live comm process did not report",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_for_comm(&self, pid: u32, comm: &[u8]) -> io::Result<()> {
        let end = Instant::now() + Duration::from_secs(20);
        let mut want = comm.to_vec();
        want.push(b'\n');
        loop {
            if self
                .run(&["cat", &format!("/proc/{pid}/comm")])
                .is_ok_and(|got| got == want)
            {
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "a live process's comm did not change",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The container.
    #[must_use]
    pub fn container(&self) -> &str {
        &self.container
    }

    /// The live processes, in [`COMM_NAMES`] order.
    #[must_use]
    pub fn procs(&self) -> &[LiveProc] {
        &self.procs
    }

    /// The current whole `/proc/<pid>/stat` text of a process inside the container.
    ///
    /// # Errors
    /// The read failed.
    pub fn read_stat(&self, pid: u32) -> io::Result<Vec<u8>> {
        self.run(&["cat", &format!("/proc/{pid}/stat")])
    }
}

impl Drop for LiveComm {
    fn drop(&mut self) {
        for p in &self.procs {
            if p.expected_process_group > 1 {
                let _ = docker_exec_run(
                    &self.container,
                    &[
                        "/bin/sh",
                        "-c",
                        "kill -s KILL -\"$1\"",
                        "sh",
                        &p.expected_process_group.to_string(),
                    ],
                    None,
                    &[],
                    Duration::from_secs(30),
                );
            }
        }
        let _ = self.run(&["rm", "-rf", &self.dir]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_fixtures_match_the_shared_parser() {
        let all = Fixtures::synthetic();
        assert_eq!(all.len(), COMM_NAMES.len() + 7);
        for f in &all {
            assert_eq!(
                heimdall_domain::procstat::parse(&f.text),
                f.expected,
                "{}",
                f.label
            );
        }
        // The naive whitespace count is wrong as soon as comm holds a space.
        let space = &all[1];
        assert_ne!(
            Fixtures::naive_field5(&space.text).as_deref(),
            Some(space.expected.unwrap().process_group.to_string().as_str())
        );
    }
}
