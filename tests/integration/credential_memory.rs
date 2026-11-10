//! m03-plan U1 vault and memory-protection tests (hosted by heimdall-credential;
//! ADR-0008 D1, D13 item 8; §17.1 item 17).
//!
//! Process-wide hardening is tested in **child processes** this test spawns (the test
//! binary re-run with `--exact u1_memory_child_entry`, the repository's crash-child
//! pattern), never in the test runner: `harden_process` lowers the **hard** core limit
//! to 0 for the rest of the process's life and, on Linux, makes it non-dumpable
//! (`/proc/self/*` becomes root-owned), which would change what every other test in
//! this runner, and every child it spawns afterwards, can do. The RLIMIT_MEMLOCK
//! child runs under `sh -c 'ulimit -l 0; exec …'` for the same reason. Each child is
//! waited for, or killed by its exact `Child` handle; its report goes to a file in a
//! scratch directory removed on drop. No secret is written there.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use heimdall_credential::sys::{self, harden_process};
use heimdall_credential::vault::{KeyVault, VaultError, VaultSlot};
#[cfg(unix)]
use heimdall_testkit::assert_no_canary;
#[cfg(unix)]
use heimdall_testkit::home::Scratch;
use ssh_key::{HashAlg, PublicKey, Signature, SshSig};

const CHILD_MODE: &str = "HM_U1_MEMORY_CHILD";
const CHILD_OUT: &str = "HM_U1_MEMORY_OUT";

/// Child-process body for the hardening tests; a no-op in a normal test run.
#[test]
fn u1_memory_child_entry() {
    let (Ok(mode), Ok(out)) = (std::env::var(CHILD_MODE), std::env::var(CHILD_OUT)) else {
        return;
    };
    let out = Path::new(&out);
    let shell_limits = || -> String {
        let o = Command::new("/bin/sh")
            .args(["-c", "ulimit -c; ulimit -H -c"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(",")
    };
    match mode.as_str() {
        "harden" => {
            let before = shell_limits();
            let report = harden_process();
            let after = shell_limits();
            let proc_limits = std::fs::read_to_string("/proc/self/limits")
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find(|l| l.starts_with("Max core file size"))
                        .map(|l| {
                            l.split_whitespace()
                                .skip(4)
                                .take(2)
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                })
                .unwrap_or_else(|| "absent".to_owned());
            std::fs::write(
                out,
                format!(
                    "dumpable={:?}\ncore_limit={:?}\nmlock_ok={}\nbefore={before}\nafter={after}\nproc={proc_limits}\n",
                    report.dumpable, report.core_limit, report.mlock_ok
                ),
            )
            .unwrap();
        }
        "mlock" => {
            let vault = KeyVault::new();
            let (slot, info) = vault.generate_ed25519().unwrap();
            let signature = vault.sign(&slot, b"u1 degraded").unwrap();
            let verified = verifies(&info.public_key().unwrap(), &vault, &slot);
            let mut page = vec![0u8; sys::page_size()];
            let probe = sys::lock_pages(&mut page);
            std::fs::write(
                out,
                format!(
                    "locked={:?}\nprobe={}\nprobe_error={}\nsignature_len={}\nverified={verified}\n",
                    vault.pages_locked(&slot),
                    probe.is_locked(),
                    probe.os_error().is_some(),
                    signature.len()
                ),
            )
            .unwrap();
        }
        "signer" | "control" => {
            // The signer hardens before any key exists (ADR-0008 D1); the control does
            // not. Both hold a K_env and wait to be attached to, then killed.
            let report = (mode == "signer").then(harden_process);
            let vault = KeyVault::new();
            let (_slot, _info) = vault.generate_ed25519().unwrap();
            std::fs::write(
                out,
                format!("ready dumpable={:?}\n", report.and_then(|r| r.dumpable)),
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
        other => panic!("unknown child mode {other}"),
    }
}

/// Run the child entry in `mode`, wait for it, and return its report.
#[cfg(unix)]
fn run_child(mode: &str, wrap_memlock_zero: bool) -> String {
    let scratch = Scratch::new().unwrap();
    let out = scratch.path().join("report");
    let exe = std::env::current_exe().unwrap();
    let args = [
        "--exact",
        "u1_memory_child_entry",
        "--nocapture",
        "--test-threads",
        "1",
    ];
    let mut cmd = if wrap_memlock_zero {
        let mut c = Command::new("/bin/sh");
        c.arg("-c")
            .arg("ulimit -l 0 && exec \"$0\" \"$@\"")
            .arg(&exe)
            .args(args);
        c
    } else {
        let mut c = Command::new(&exe);
        c.args(args);
        c
    };
    let o = cmd
        .env(CHILD_MODE, mode)
        .env(CHILD_OUT, &out)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_no_canary(&String::from_utf8_lossy(&o.stdout));
    assert_no_canary(&String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{mode} child exit {:?}", o.status);
    std::fs::read_to_string(&out).unwrap()
}

#[cfg(unix)]
fn field<'a>(report: &'a str, name: &str) -> &'a str {
    report
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in the child report"))
}

/// An SSHSIG over `msg` made by the vault key, verified by `ssh-key`.
fn verifies(public: &PublicKey, vault: &KeyVault, slot: &VaultSlot) -> bool {
    let msg = b"u1 vault message";
    let data = SshSig::signed_data("u1@heimdall", HashAlg::Sha512, msg).unwrap();
    let blob = vault.sign(slot, &data).unwrap();
    let signature = Signature::try_from(blob.as_slice()).unwrap();
    let sig = SshSig::new(
        public.key_data().clone(),
        "u1@heimdall",
        HashAlg::Sha512,
        signature,
    )
    .unwrap();
    public.verify("u1@heimdall", msg, &sig).is_ok()
}

// --- the vault ------------------------------------------------------------------------------

#[test]
fn ed25519_key_signs_and_verifies() {
    let vault = KeyVault::new();
    let (slot, info) = vault.generate_ed25519().unwrap();
    // The public half is self-consistent.
    let public = info.public_key().unwrap();
    assert_eq!(public.algorithm().as_str(), "ssh-ed25519");
    assert_eq!(public.to_bytes().unwrap(), info.blob);
    assert_eq!(
        public.fingerprint(HashAlg::Sha256).to_string(),
        info.fingerprint
    );
    assert_eq!(
        PublicKey::from_openssh(&info.openssh_line)
            .unwrap()
            .key_data(),
        public.key_data()
    );
    assert_eq!(
        info.openssh_line.split_whitespace().count(),
        2,
        "no comment"
    );
    assert_eq!(vault.public_key(&slot), Some(info.clone()));
    // The signature is the SSH blob: string "ssh-ed25519", string signature[64].
    let blob = vault.sign(&slot, b"data").unwrap();
    let signature = Signature::try_from(blob.as_slice()).unwrap();
    assert_eq!(signature.algorithm().as_str(), "ssh-ed25519");
    assert_eq!(signature.as_bytes().len(), 64);
    assert_eq!(blob.len(), 4 + 11 + 4 + 64);
    // Ed25519 is deterministic: same key, same data, same signature.
    assert_eq!(vault.sign(&slot, b"data").unwrap(), blob);
    assert_ne!(vault.sign(&slot, b"other").unwrap(), blob);
    // It verifies (ssh-key, through an SSHSIG over the same key), and a wrong message
    // or key does not.
    assert!(verifies(&public, &vault, &slot));
    let data = SshSig::signed_data("u1@heimdall", HashAlg::Sha512, b"m").unwrap();
    let sig = SshSig::new(
        public.key_data().clone(),
        "u1@heimdall",
        HashAlg::Sha512,
        Signature::try_from(vault.sign(&slot, &data).unwrap().as_slice()).unwrap(),
    )
    .unwrap();
    assert!(public.verify("u1@heimdall", b"m", &sig).is_ok());
    assert!(public.verify("u1@heimdall", b"n", &sig).is_err());
    let (_, other) = vault.generate_ed25519().unwrap();
    assert_ne!(other.blob, info.blob, "fresh keys differ");
    // OpenSSH verifies it too (ssh-keygen -Y check-novalidate), where installed.
    #[cfg(unix)]
    if let Some(keygen) = heimdall_testkit::home::find_program("ssh-keygen") {
        let scratch = Scratch::new().unwrap();
        let sig_file = scratch.path().join("m.sig");
        std::fs::write(&sig_file, sig.to_pem(ssh_key::LineEnding::LF).unwrap()).unwrap();
        let check = |msg: &[u8]| {
            let input = scratch.path().join("m");
            std::fs::write(&input, msg).unwrap();
            Command::new(&keygen)
                .args(["-Y", "check-novalidate", "-n", "u1@heimdall", "-s"])
                .arg(&sig_file)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(std::fs::File::open(&input).unwrap())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        };
        assert!(check(b"m"), "ssh-keygen verifies the vault signature");
        assert!(!check(b"n"), "and refuses another message");
    }
    // Slots are random 128-bit handles; the hex is the persisted key_handle_ref.
    assert_eq!(slot.to_hex().len(), 32);
    assert_eq!(VaultSlot::from_hex(&slot.to_hex()), Some(slot));
    // Keys are page-locked under ordinary limits (the degraded case is its own test).
    assert_eq!(vault.pages_locked(&slot), Some(true));
}

/// The test seed (debug builds only; m03-plan U0b row 16).
#[cfg(debug_assertions)]
#[test]
fn seeded_vault_is_deterministic_and_published() {
    let a = KeyVault::with_test_seed(b"hm-u1-seed").unwrap();
    let b = KeyVault::with_test_seed(b"hm-u1-seed").unwrap();
    let c = KeyVault::with_test_seed(b"hm-u1-other").unwrap();
    let (sa, ia) = a.generate_ed25519().unwrap();
    let (sb, ib) = b.generate_ed25519().unwrap();
    let (_, ic) = c.generate_ed25519().unwrap();
    assert_eq!(ia, ib, "same seed, same first key");
    assert_ne!(sa, sb, "slots stay random");
    assert_ne!(ia.blob, ic.blob);
    let (_, ia2) = a.generate_ed25519().unwrap();
    assert_ne!(ia2.blob, ia.blob, "the second key is the next derivation");
    // The one derivation rule, shared with heimdall_testkit::managed::seeded_k_env_nth:
    // SHA-256(b"heimdall-test-key-seed/k_env/v1\0" || u64_be(n) || seed).
    for (n, info) in [(0u64, &ia), (1, &ia2)] {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(b"heimdall-test-key-seed/k_env/v1\0");
        h.update(n.to_be_bytes());
        h.update(b"hm-u1-seed");
        let expected: [u8; 32] = h.finalize().into();
        let published = heimdall_credential::vault::seeded_private_key(b"hm-u1-seed", n).unwrap();
        assert!(*published == expected, "known answer for key {n}");
        let public = PublicKey::from(ssh_key::private::Ed25519Keypair::from_seed(&expected).public);
        assert_eq!(public.to_bytes().unwrap(), info.blob, "key {n}");
    }
    assert_eq!(
        KeyVault::with_test_seed(&[]).err(),
        Some(VaultError::InvalidSeed)
    );
}

#[test]
fn vault_destroy_removes_slot_and_sign_fails() {
    let vault = KeyVault::new();
    let (a, _) = vault.generate_ed25519().unwrap();
    let (b, info_b) = vault.generate_ed25519().unwrap();
    assert_eq!(vault.len(), 2);
    assert!(vault.contains(&a) && vault.contains(&b));
    vault.sign(&a, b"before").unwrap();

    vault.destroy(&a);
    assert!(!vault.contains(&a));
    assert_eq!(vault.sign(&a, b"after"), Err(VaultError::NoSuchSlot));
    assert_eq!(vault.public_key(&a), None);
    assert_eq!(vault.pages_locked(&a), None);
    assert_eq!(vault.len(), 1);
    // Idempotent; the other key is untouched.
    vault.destroy(&a);
    assert!(vault.contains(&b));
    assert_eq!(vault.public_key(&b), Some(info_b));
    vault.sign(&b, b"still").unwrap();
    // A slot from another vault, or a parsed handle that was never generated here.
    let other = KeyVault::new();
    let (foreign, _) = other.generate_ed25519().unwrap();
    assert!(!vault.contains(&foreign));
    assert_eq!(vault.sign(&foreign, b"x"), Err(VaultError::NoSuchSlot));
    let made_up = VaultSlot::from_hex("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(vault.sign(&made_up, b"x"), Err(VaultError::NoSuchSlot));
    // A destroyed slot never comes back, and a new key gets a new slot.
    let (c, _) = vault.generate_ed25519().unwrap();
    assert_ne!(c, a);
    assert!(!vault.contains(&a));
    // destroy_all zeroizes everything (process exit, TIME_UNCERTAIN closure).
    vault.destroy_all();
    assert!(vault.is_empty());
    assert_eq!(vault.sign(&b, b"x"), Err(VaultError::NoSuchSlot));
    assert_eq!(vault.sign(&c, b"x"), Err(VaultError::NoSuchSlot));
}

/// The compile-time proof is the module's compile-fail doc tests (`vault` docs, run by
/// `cargo test --doc`); this test asks the same questions at run time, with controls
/// that show the probe detects an implementation.
#[test]
fn secret_key_has_no_clone_debug_serialize() {
    macro_rules! implements {
        ($ty:ty: $tr:path) => {{
            struct Probe<T>(std::marker::PhantomData<T>);
            #[allow(dead_code)] // one of the two traits is unused per call: the answer
            trait Yes {
                fn get(&self) -> bool {
                    true
                }
            }
            impl<T: $tr> Yes for Probe<T> {}
            #[allow(dead_code)]
            trait No {
                fn get(&self) -> bool {
                    false
                }
            }
            impl<T> No for &Probe<T> {}
            (&Probe::<$ty>(std::marker::PhantomData)).get()
        }};
    }
    use heimdall_credential::vault::SecretKey;
    // Controls: the probe sees each trait where it exists.
    assert!(implements!(String: Clone));
    assert!(implements!(String: std::fmt::Debug));
    assert!(implements!(String: std::fmt::Display));
    assert!(implements!(String: serde::Serialize));
    assert!(implements!(String: serde::de::DeserializeOwned));
    // SecretKey has none of them.
    assert!(!implements!(SecretKey: Clone));
    assert!(!implements!(SecretKey: std::fmt::Debug));
    assert!(!implements!(SecretKey: std::fmt::Display));
    assert!(!implements!(SecretKey: serde::Serialize));
    assert!(!implements!(SecretKey: serde::de::DeserializeOwned));
    // The vault's Debug shows a count, never key material.
    let vault = KeyVault::new();
    let (slot, _) = vault.generate_ed25519().unwrap();
    let text = format!("{vault:?}");
    assert_eq!(text, "KeyVault { keys: Some(1), .. }");
    assert!(!text.contains(&slot.to_hex()));
}

// --- memory protection ----------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn mlock_failure_degrades_not_refuses() {
    // Control: under the ordinary limits the same child locks its key's page.
    let normal = run_child("mlock", false);
    assert_eq!(field(&normal, "locked"), "Some(true)", "control: locked");
    assert_eq!(field(&normal, "probe"), "true");
    // RLIMIT_MEMLOCK 0: the lock fails, and the key is still generated and signs.
    let root = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);
    assert!(
        !root,
        "running as root: RLIMIT_MEMLOCK does not bind (CAP_IPC_LOCK); run as a non-root user"
    );
    let degraded = run_child("mlock", true);
    assert_eq!(
        field(&degraded, "probe"),
        "false",
        "the OS refused the lock"
    );
    assert_eq!(field(&degraded, "probe_error"), "true");
    assert_eq!(
        field(&degraded, "locked"),
        "Some(false)",
        "recorded as a degraded mitigation"
    );
    assert_eq!(
        field(&degraded, "signature_len"),
        "83",
        "the key still signs"
    );
    assert_eq!(field(&degraded, "verified"), "true");
}

#[cfg(unix)]
#[test]
fn core_dumps_disabled_after_harden() {
    let report = run_child("harden", false);
    // getrlimit read back by harden_process itself, and by a shell the hardened child
    // spawned afterwards (it inherits the limits): soft and hard both 0.
    assert_eq!(field(&report, "core_limit"), "Some(0)");
    assert_eq!(field(&report, "after"), "0,0", "ulimit -c; ulimit -H -c");
    assert_eq!(field(&report, "mlock_ok"), "true");
    #[cfg(target_os = "linux")]
    {
        assert_eq!(field(&report, "dumpable"), "Some(false)");
        assert_eq!(field(&report, "proc"), "0,0", "/proc/self/limits");
    }
    #[cfg(not(target_os = "linux"))]
    assert_eq!(field(&report, "dumpable"), "None", "no dumpable flag here");
}

/// The ptrace probe and its positive control (ADR-0008 D13 item 8; §17.1 item 17).
#[cfg(target_os = "linux")]
mod ptrace {
    use std::io::{Read, Seek, SeekFrom};
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    use super::*;

    /// `/proc/sys/kernel/yama/ptrace_scope`, or `absent`.
    pub fn ptrace_scope() -> String {
        std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "absent".to_owned())
    }

    /// A child in `mode` (`signer`: hardened, `control`: not), ready, with a K_env.
    pub struct Held {
        pub child: Child,
        _scratch: Scratch,
    }

    impl Drop for Held {
        fn drop(&mut self) {
            // The exact PID, through the handle.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    pub fn spawn(mode: &str) -> Held {
        let scratch = Scratch::new().unwrap();
        let out = scratch.path().join("ready");
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "u1_memory_child_entry",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(CHILD_MODE, mode)
            .env(CHILD_OUT, &out)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        while !std::fs::read_to_string(&out).is_ok_and(|t| t.starts_with("ready")) {
            assert!(Instant::now() < end, "{mode} child not ready in 30 s");
            std::thread::sleep(Duration::from_millis(10));
        }
        Held {
            child,
            _scratch: scratch,
        }
    }

    /// Attach to `pid` for memory access the way a same-user debugger would: open
    /// `/proc/<pid>/mem` (the kernel's `ptrace_may_access(PTRACE_MODE_ATTACH_FSCREDS)`,
    /// the predicate `PTRACE_ATTACH` checks, Yama included) and read a byte of its
    /// first readable mapping (from `/proc/<pid>/maps`, `PTRACE_MODE_READ`).
    pub fn attach(pid: u32) -> Result<(), std::io::ErrorKind> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.kind())?;
        let start = maps
            .lines()
            .find(|l| {
                l.split_whitespace()
                    .nth(1)
                    .is_some_and(|p| p.starts_with('r'))
            })
            .and_then(|l| l.split('-').next())
            .and_then(|a| u64::from_str_radix(a, 16).ok())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).map_err(|e| e.kind())?;
        mem.seek(SeekFrom::Start(start)).map_err(|e| e.kind())?;
        let mut byte = [0u8; 1];
        mem.read_exact(&mut byte).map_err(|e| e.kind())
    }
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::print_stderr)]
fn dumpable_control_attach_succeeds() {
    let scope = ptrace::ptrace_scope();
    let control = ptrace::spawn("control");
    let result = ptrace::attach(control.child.id());
    eprintln!("hm-u1 ptrace record: ptrace_scope={scope} control_attach={result:?}");
    assert_eq!(
        result,
        Ok(()),
        "a dumpable same-user child must be attachable (ptrace_scope={scope})"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::print_stderr)]
fn linux_signer_not_ptraceable_by_same_user() {
    let scope = ptrace::ptrace_scope();
    // The positive control, attached the same way: without it the signer's refusal
    // would prove nothing (F22).
    let control = ptrace::spawn("control");
    let control_result = ptrace::attach(control.child.id());
    drop(control);
    let signer = ptrace::spawn("signer");
    let signer_result = ptrace::attach(signer.child.id());
    eprintln!(
        "hm-u1 ptrace record: ptrace_scope={scope} control_attach={control_result:?} \
         signer_attach={signer_result:?}"
    );
    assert_eq!(
        control_result,
        Ok(()),
        "inconclusive: the dumpable control could not be attached (ptrace_scope={scope}), \
         so the signer's result does not count"
    );
    assert_eq!(
        signer_result,
        Err(std::io::ErrorKind::PermissionDenied),
        "the hardened signer must refuse a same-user attach (ptrace_scope={scope})"
    );
}
