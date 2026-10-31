//! x4-windows-rust: spike for G02 round 4 / X4.
//! Subcommands (each prints one JSON object per line, never a secret):
//!   dpapi [--op all|protect|unprotect] [--out F|--in F] [--iterations N]
//!   cng --op probe|inventory|create|sign|verify-pub|delete|all [--provider software|platform] [--name N]
//!       [--prefix P] [--pub-out F|--pub-in F] [--sig-out F|--sig-in F] [--msg M] [--iterations N]
//!   pipe-server [--name N] [--count N] [--timeout S] [--expect-sid SID] | pipe-client [--name N] [--level L]
//! M00-T04-x4-stores adaptation: adds the dpapi protect/unprotect split (two processes), cng inventory,
//! export-policy / impl-type readback, private-export attempts, timed signing, file output of the public
//! key and one signature, and verify-pub (BCrypt, public key only). Existing ops keep their fields.
#![cfg(windows)]

mod cng;
mod dpapi;
mod pipe;

use std::fmt::Write as _;
use std::time::Instant;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Microseconds elapsed since `t`.
pub fn us(t: Instant) -> u128 {
    t.elapsed().as_micros()
}

/// Minimal JSON line builder (no serde: keeps the dependency set at one crate).
#[derive(Default)]
pub struct J(String);
impl J {
    pub fn new() -> J {
        J::default()
    }
    fn key(&mut self, k: &str) {
        if !self.0.is_empty() {
            self.0.push(',');
        }
        let _ = write!(self.0, "\"{k}\":");
    }
    pub fn s(&mut self, k: &str, v: &str) -> &mut J {
        self.key(k);
        self.0.push('"');
        for c in v.chars() {
            match c {
                '"' | '\\' => {
                    self.0.push('\\');
                    self.0.push(c)
                }
                c if (c as u32) < 0x20 => {}
                c => self.0.push(c),
            }
        }
        self.0.push('"');
        self
    }
    pub fn b(&mut self, k: &str, v: bool) -> &mut J {
        self.key(k);
        self.0.push_str(if v { "true" } else { "false" });
        self
    }
    pub fn n(&mut self, k: &str, v: i64) -> &mut J {
        self.key(k);
        let _ = write!(self.0, "{v}");
        self
    }
    /// Timing summary in microseconds: n, first, min, median, max, mean.
    pub fn stats(&mut self, p: &str, v: &[u128]) -> &mut J {
        if v.is_empty() {
            return self.n(&format!("{p}_n"), 0);
        }
        let mut s = v.to_vec();
        s.sort_unstable();
        let mean = s.iter().sum::<u128>() / s.len() as u128;
        self.n(&format!("{p}_n"), s.len() as i64)
            .n(&format!("{p}_first_us"), v[0] as i64)
            .n(&format!("{p}_min_us"), s[0] as i64)
            .n(&format!("{p}_median_us"), s[s.len() / 2] as i64)
            .n(&format!("{p}_max_us"), s[s.len() - 1] as i64)
            .n(&format!("{p}_mean_us"), mean as i64)
    }
    pub fn emit(&self) {
        println!("{{{}}}", self.0);
    }
}

pub struct Args(Vec<String>);
impl Args {
    pub fn get(&self, k: &str, d: &str) -> String {
        self.0
            .windows(2)
            .find(|w| w[0] == k)
            .map(|w| w[1].clone())
            .unwrap_or_else(|| d.to_string())
    }
    pub fn iterations(&self) -> usize {
        self.get("--iterations", "1")
            .parse()
            .unwrap_or(1)
            .clamp(1, 1000)
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = a.first().cloned() else {
        eprintln!("usage: x4 dpapi|cng|pipe-server|pipe-client [flags]");
        std::process::exit(2);
    };
    let args = Args(a);
    let name = args.get("--name", "heimdall-x4-spike");
    let ok = match cmd.as_str() {
        "dpapi" => match args.get("--op", "all").as_str() {
            "protect" | "unprotect" => dpapi::run_split(&args),
            _ => dpapi::run(),
        },
        "cng" => cng::run(
            &args.get("--op", "all"),
            &args.get("--provider", "software"),
            &name,
            &args,
        ),
        "pipe-server" => pipe::server(
            &name,
            args.get("--count", "1").parse().unwrap_or(1),
            args.get("--timeout", "30").parse().unwrap_or(30),
            &args.get("--expect-sid", ""),
        ),
        "pipe-client" => pipe::client(&name, &args.get("--level", "identification")),
        _ => {
            eprintln!("unknown subcommand");
            std::process::exit(2)
        }
    };
    std::process::exit(if ok { 0 } else { 1 });
}
