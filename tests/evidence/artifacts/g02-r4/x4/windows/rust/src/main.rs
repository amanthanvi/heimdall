//! x4-windows-rust: compile-only spike for G02 round 4 / X4.
//! Subcommands (each prints one JSON object per line, never a secret):
//!   dpapi | cng --op probe|create|sign|delete|all [--provider software|platform] [--name N]
//!   pipe-server [--name N] [--count N] [--timeout S] [--expect-sid SID] | pipe-client [--name N] [--level L]
#![cfg(windows)]

mod cng;
mod dpapi;
mod pipe;

use std::fmt::Write as _;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
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
    pub fn emit(&self) {
        println!("{{{}}}", self.0);
    }
}

struct Args(Vec<String>);
impl Args {
    fn get(&self, k: &str, d: &str) -> String {
        self.0
            .windows(2)
            .find(|w| w[0] == k)
            .map(|w| w[1].clone())
            .unwrap_or_else(|| d.to_string())
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
        "dpapi" => dpapi::run(),
        "cng" => cng::run(
            &args.get("--op", "all"),
            &args.get("--provider", "software"),
            &name,
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
