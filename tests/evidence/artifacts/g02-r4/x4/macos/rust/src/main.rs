//! hm-x4-rust: G02 round-4 X4 macOS spike (disposable evidence, not production code).
//!
//!   hm-x4-rust keychain <file-keychain-path>   add/read/delete one generic password
//!   hm-x4-rust se                              ephemeral Secure Enclave P-256 sign/verify
//!   hm-x4-rust dpprobe                         read-only data-protection keychain probe
//!
//! Secrets are generated in-process and never printed. Exit 0 = step succeeded.
use core_foundation::base::{CFType, TCFType};
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::random::SecRandom;
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use security_framework_sys::item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave};
use std::process::exit;

/// Placeholder team prefix: no Apple team ID exists for this spike.
const DP_GROUP: &str = "XXXXXXXXXX.dev.heimdall.x4";

fn rnd(n: usize) -> String {
    let mut b = vec![0u8; n];
    SecRandom::default().copy_bytes(&mut b).expect("random");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn status<T>(r: &Result<T, security_framework::base::Error>) -> i32 {
    r.as_ref().map(|_| 0).unwrap_or_else(|e| e.code())
}

fn keychain(path: &str) -> bool {
    let (svc, acct) = ("hm-x4-svc", "hm-x4-acct");
    let secret = format!("hm-x4-not-a-canary-{}", rnd(16)).into_bytes();
    let kc = SecKeychain::open(path);
    println!("keychain open osstatus={}", status(&kc));
    let Ok(kc) = kc else { return false };
    let add = kc.add_generic_password(svc, acct, &secret);
    println!("keychain add osstatus={}", status(&add));
    let read = kc.find_generic_password(svc, acct);
    println!("keychain read osstatus={}", status(&read));
    let matches = matches!(&read, Ok((pw, _)) if pw.as_ref() == secret.as_slice());
    if read.is_ok() {
        println!(
            "keychain read_mismatch osstatus={}",
            if matches { 0 } else { 1 }
        );
    }
    // SecKeychainItem::delete() discards its OSStatus, so delete through SecItemDelete
    // scoped to this keychain to observe the status.
    let del = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .keychains(std::slice::from_ref(&kc))
        .service(svc)
        .account(acct)
        .delete();
    println!("keychain delete osstatus={}", status(&del));
    let after = kc.find_generic_password(svc, acct);
    println!("keychain read_after_delete osstatus={}", status(&after));
    add.is_ok() && matches && del.is_ok() && status(&after) == -25300
}

fn se() -> bool {
    let ac = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )
    .expect("access control");
    let mut opts = GenerateKeyOptions::default();
    // No set_location(): the crate then sets kSecAttrIsPermanent = false (ephemeral key).
    opts.set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(ac);
    let key = match SecKey::new(&opts) {
        Ok(k) => k,
        Err(e) => {
            println!("se create_cferror={}", e.code());
            return false;
        }
    };
    // kSecAttrTokenID / kSecAttrTokenIDSecureEnclave are extern statics: reading them is unsafe.
    let (tok_key, tok_se) = unsafe {
        (
            CFString::wrap_under_get_rule(kSecAttrTokenID),
            CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave),
        )
    };
    let is_se = key
        .attributes()
        .find(tok_key.as_CFTypeRef())
        .map(|v| unsafe { CFType::wrap_under_get_rule(*v) } == tok_se.as_CFType())
        .unwrap_or(false);
    let priv_exportable = key.external_representation().is_some();
    let public = key.public_key().expect("public key");
    let pub_len = public
        .external_representation()
        .map(|d| d.len())
        .unwrap_or(0);
    println!("se create_cferror=0 is_secure_enclave_token={is_se} private_exportable={priv_exportable} public_len={pub_len}");
    let msg = format!("heimdall g02 r4 x4 message {}", rnd(8)).into_bytes();
    let alg = Algorithm::ECDSASignatureMessageX962SHA256;
    let sig = match key.create_signature(alg, &msg) {
        Ok(s) => s,
        Err(e) => {
            println!("se sign_cferror={}", e.code());
            return false;
        }
    };
    let ok = public.verify_signature(alg, &msg, &sig).unwrap_or(false);
    let mut tampered = msg.clone();
    tampered[0] ^= 1;
    let tampered_ok = public
        .verify_signature(alg, &tampered, &sig)
        .unwrap_or(false);
    println!(
        "se sign_cferror=0 sig_der_len={} verify={ok} verify_tampered={tampered_ok}",
        sig.len()
    );
    is_se && !priv_exportable && pub_len == 65 && ok && !tampered_ok
}

fn dp_probe(group: Option<&str>) -> i32 {
    let svc = format!("hm-x4-dp-probe-{}", rnd(8));
    let mut q = ItemSearchOptions::new();
    // ignore_legacy_keychains() sets kSecUseDataProtectionKeychain = true. Read-only query.
    q.class(ItemClass::generic_password())
        .service(&svc)
        .ignore_legacy_keychains();
    if let Some(g) = group {
        q.access_group(g);
    }
    status(&q.search())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ok = match (args.get(1).map(String::as_str), args.len()) {
        (Some("keychain"), 3) => keychain(&args[2]),
        (Some("se"), 2) => se(),
        (Some("dpprobe"), 2) => {
            // -25300 = errSecItemNotFound; -34018 = errSecMissingEntitlement.
            let a = dp_probe(None);
            let b = dp_probe(Some(DP_GROUP));
            println!("dpprobe no_access_group osstatus={a}");
            println!("dpprobe access_group={DP_GROUP} osstatus={b}");
            a == -25300 && b == -25300
        }
        _ => {
            eprintln!("usage: hm-x4-rust keychain <path> | se | dpprobe");
            exit(2)
        }
    };
    exit(if ok { 0 } else { 1 })
}
