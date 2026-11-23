//! Boundary 9: a backup file the user restores from, and a recovery bundle. The passphrase
//! is a fixed fixture string; no real key exists.
#![no_main]
use heimdall_contract::issuer::RecoveryBundle;
use heimdall_credential::cert::SecretCaKey;
use heimdall_issuer::backup::fingerprint_from_file_stem;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SecretCaKey::decrypt_openssh(data, b"fixture passphrase");
    let _ = serde_json::from_slice::<RecoveryBundle>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = fingerprint_from_file_stem(text);
    }
});
