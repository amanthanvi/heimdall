// Build script: records the pinned ratatui/crossterm versions from Cargo.lock and the
// rustc version, so `version --json` reports what was actually compiled in.
// No network, no native compilation.
use std::process::Command;

fn lock_version(lock: &str, name: &str) -> String {
    let needle = format!("name = \"{name}\"\nversion = \"");
    match lock.find(&needle) {
        Some(i) => {
            let rest = &lock[i + needle.len()..];
            rest[..rest.find('"').unwrap_or(0)].to_string()
        }
        None => "unknown".to_string(),
    }
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");
    let lock = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
    println!(
        "cargo:rustc-env=HEIMDALL_PROTO_RATATUI_VERSION={}",
        lock_version(&lock, "ratatui")
    );
    println!(
        "cargo:rustc-env=HEIMDALL_PROTO_CROSSTERM_VERSION={}",
        lock_version(&lock, "crossterm")
    );
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let v = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "rustc unknown".into());
    println!("cargo:rustc-env=HEIMDALL_PROTO_RUSTC_VERSION={v}");
}
