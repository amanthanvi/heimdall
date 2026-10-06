use crate::J;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: b.len() as u32,
        pbData: b.as_ptr() as *mut u8,
    }
}

/// CryptProtectData, user scope, UI forbidden. `entropy` may be empty.
fn protect(plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, u32> {
    let (inb, ent) = (blob(plain), blob(entropy));
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: all pointers outlive the call; `out` is freed with LocalFree below.
    unsafe {
        let descr = crate::wide("heimdall-x4");
        let e = if entropy.is_empty() {
            null()
        } else {
            &ent as *const _
        };
        if CryptProtectData(
            &inb,
            descr.as_ptr(),
            e,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        ) == 0
        {
            return Err(GetLastError());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

fn unprotect(ct: &[u8], entropy: &[u8]) -> Result<Vec<u8>, u32> {
    let (inb, ent) = (blob(ct), blob(entropy));
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let mut descr: *mut u16 = null_mut();
    // SAFETY: as above; `descr` is allocated by the API and freed with LocalFree.
    unsafe {
        let e = if entropy.is_empty() {
            null()
        } else {
            &ent as *const _
        };
        if CryptUnprotectData(
            &inb,
            &mut descr,
            e,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        ) == 0
        {
            return Err(GetLastError());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        if !descr.is_null() {
            LocalFree(descr as _);
        }
        Ok(v)
    }
}

/// Round trip, entropy-mismatch rejection and tamper rejection. Plaintext is a fixed non-secret marker.
pub fn run() -> bool {
    let plain = b"heimdall-x4-dpapi-roundtrip-marker";
    let entropy = b"heimdall-x4-entropy";
    let mut j = J::new();
    j.s("op", "dpapi").s("scope", "current-user");
    let ct = match protect(plain, entropy) {
        Ok(c) => c,
        Err(e) => {
            j.b("ok", false).n("win32_error", e as i64).emit();
            return false;
        }
    };
    j.n("ciphertext_len", ct.len() as i64);
    j.b(
        "ciphertext_differs",
        !ct.windows(plain.len()).any(|w| w == plain),
    );
    let rt = unprotect(&ct, entropy).map(|b| b == plain).unwrap_or(false);
    let wrong = unprotect(&ct, b"wrong-entropy").is_err();
    let mut bad = ct.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0xff;
    let tamper = unprotect(&bad, entropy).is_err();
    j.b("roundtrip_ok", rt)
        .b("wrong_entropy_rejected", wrong)
        .b("tamper_rejected", tamper);
    let ok = rt && wrong && tamper;
    j.b("ok", ok).emit();
    ok
}
