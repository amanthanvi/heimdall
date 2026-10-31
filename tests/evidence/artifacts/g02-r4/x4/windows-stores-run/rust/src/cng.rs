use crate::{Args, J, hex, us, wide};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::time::Instant;
use windows_sys::Win32::Foundation::{NTE_BAD_FLAGS, NTE_BAD_KEYSET, NTE_NO_MORE_ITEMS};
use windows_sys::Win32::Security::Cryptography::*;

type Res<T> = Result<T, (&'static str, i32)>;

fn st(f: &'static str, r: i32) -> Res<()> {
    if r == 0 { Ok(()) } else { Err((f, r)) }
}

fn hx(r: i32) -> String {
    format!("0x{:08X}", r as u32)
}

fn open_provider(name: *const u16) -> Res<NCRYPT_PROV_HANDLE> {
    let mut h = 0;
    // SAFETY: out-pointer is a live local; name is a NUL-terminated wide constant.
    st("NCryptOpenStorageProvider", unsafe {
        NCryptOpenStorageProvider(&mut h, name, 0)
    })?;
    Ok(h)
}

fn free(h: usize) {
    // SAFETY: handle came from NCrypt.
    unsafe { NCryptFreeObject(h) };
}

/// Returns the key handle and the NCryptSetProperty(Export Policy = 0) status (0 = accepted).
fn create_key(p: NCRYPT_PROV_HANDLE, name: &str) -> Res<(NCRYPT_KEY_HANDLE, i32)> {
    let mut k = 0;
    let n = wide(name);
    // SAFETY: no NCRYPT_OVERWRITE_KEY_FLAG, so a name collision fails with NTE_EXISTS.
    unsafe {
        st(
            "NCryptCreatePersistedKey",
            NCryptCreatePersistedKey(
                p,
                &mut k,
                BCRYPT_ECDSA_P256_ALGORITHM,
                n.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            ),
        )?;
        let pol: u32 = 0; // explicit non-exportable; non-fatal on providers that reject it
        let set = NCryptSetProperty(
            k,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &pol as *const u32 as *const u8,
            4,
            NCRYPT_SILENT_FLAG,
        );
        if let Err(e) = st(
            "NCryptFinalizeKey",
            NCryptFinalizeKey(k, NCRYPT_SILENT_FLAG),
        ) {
            free(k);
            return Err(e);
        }
        Ok((k, set))
    }
}

fn open_key(p: NCRYPT_PROV_HANDLE, name: &str) -> Res<NCRYPT_KEY_HANDLE> {
    let (mut k, n) = (0, wide(name));
    // SAFETY: as above.
    st("NCryptOpenKey", unsafe {
        NCryptOpenKey(p, &mut k, n.as_ptr(), 0, NCRYPT_SILENT_FLAG)
    })?;
    Ok(k)
}

fn export_public(k: NCRYPT_KEY_HANDLE) -> Res<Vec<u8>> {
    let mut n = 0u32;
    // SAFETY: standard two-call size/fill pattern.
    unsafe {
        st(
            "NCryptExportKey(size)",
            NCryptExportKey(
                k,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                null_mut(),
                0,
                &mut n,
                0,
            ),
        )?;
        let mut buf = vec![0u8; n as usize];
        st(
            "NCryptExportKey",
            NCryptExportKey(
                k,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                buf.as_mut_ptr(),
                n,
                &mut n,
                0,
            ),
        )?;
        buf.truncate(n as usize);
        Ok(buf)
    }
}

/// Attempt a private-key export. The bytes, if any, are zeroed and never printed or written.
/// Returns (export succeeded, status of the failing call or 0, bytes returned).
fn try_export_private(k: NCRYPT_KEY_HANDLE, blob: *const u16) -> (bool, i32, u32) {
    let mut n = 0u32;
    // SAFETY: two-call pattern; the buffer is local and wiped before drop.
    unsafe {
        let r = NCryptExportKey(
            k,
            0,
            blob,
            null(),
            null_mut(),
            0,
            &mut n,
            NCRYPT_SILENT_FLAG,
        );
        if r != 0 {
            return (false, r, 0);
        }
        let mut buf = vec![0u8; n as usize];
        let r = NCryptExportKey(
            k,
            0,
            blob,
            null(),
            buf.as_mut_ptr(),
            n,
            &mut n,
            NCRYPT_SILENT_FLAG,
        );
        for b in buf.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
        (r == 0, r, if r == 0 { n } else { 0 })
    }
}

fn get_u32(h: usize, prop: *const u16) -> Res<u32> {
    let (mut v, mut n) = (0u32, 0u32);
    // SAFETY: 4-byte out buffer.
    st("NCryptGetProperty", unsafe {
        NCryptGetProperty(h, prop, &mut v as *mut u32 as *mut u8, 4, &mut n, 0)
    })?;
    Ok(v)
}

fn get_wstr(h: usize, prop: *const u16) -> Res<String> {
    let mut n = 0u32;
    // SAFETY: two-call pattern, u16 buffer sized from the byte count.
    unsafe {
        st(
            "NCryptGetProperty(size)",
            NCryptGetProperty(h, prop, null_mut(), 0, &mut n, 0),
        )?;
        let mut buf = vec![0u16; (n as usize).div_ceil(2)];
        st(
            "NCryptGetProperty",
            NCryptGetProperty(h, prop, buf.as_mut_ptr() as *mut u8, n, &mut n, 0),
        )?;
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Ok(String::from_utf16_lossy(&buf[..end]))
    }
}

/// Export policy and implementation type of a key handle, plus private-export attempts.
fn key_props(j: &mut J, k: NCRYPT_KEY_HANDLE) {
    match get_u32(k, NCRYPT_EXPORT_POLICY_PROPERTY) {
        Ok(v) => j.n("export_policy", v as i64),
        Err((_, r)) => j.s("export_policy_status", &hx(r)),
    };
    match get_u32(k, NCRYPT_IMPL_TYPE_PROPERTY) {
        Ok(v) => j
            .n("impl_type", v as i64)
            .b("impl_hardware", v & NCRYPT_IMPL_HARDWARE_FLAG != 0)
            .b("impl_software", v & NCRYPT_IMPL_SOFTWARE_FLAG != 0),
        Err((_, r)) => j.s("impl_type_status", &hx(r)),
    };
    for (id, blob) in [
        ("eccprivateblob", BCRYPT_ECCPRIVATE_BLOB),
        ("pkcs8", NCRYPT_PKCS8_PRIVATE_KEY_BLOB),
    ] {
        let (ok, r, n) = try_export_private(k, blob);
        j.b(&format!("private_export_{id}_succeeded"), ok);
        if ok {
            j.n(&format!("private_export_{id}_len"), n as i64);
        } else {
            j.s(&format!("private_export_{id}_status"), &hx(r));
        }
    }
}

fn sha256(data: &[u8]) -> Res<[u8; 32]> {
    let mut out = [0u8; 32];
    // SAFETY: pseudo-handle (Windows 10+), output buffer is 32 bytes.
    st("BCryptHash", unsafe {
        BCryptHash(
            BCRYPT_SHA256_ALG_HANDLE,
            null(),
            0,
            data.as_ptr(),
            data.len() as u32,
            out.as_mut_ptr(),
            32,
        )
    })?;
    Ok(out)
}

/// Sign a fixed 32-byte digest, verify it, then check a tampered copy is rejected.
fn sign_verify(k: NCRYPT_KEY_HANDLE) -> Res<(usize, bool)> {
    let h: [u8; 32] = *b"heimdall-x4-cng-sign-marker-0000";
    let mut n = 0u32;
    // SAFETY: standard two-call pattern; buffers sized by the first call.
    unsafe {
        st(
            "NCryptSignHash(size)",
            NCryptSignHash(k, null(), h.as_ptr(), 32, null_mut(), 0, &mut n, 0),
        )?;
        let mut sig = vec![0u8; n as usize];
        st(
            "NCryptSignHash",
            NCryptSignHash(k, null(), h.as_ptr(), 32, sig.as_mut_ptr(), n, &mut n, 0),
        )?;
        let good = NCryptVerifySignature(k, null(), h.as_ptr(), 32, sig.as_ptr(), n, 0) == 0;
        sig[0] ^= 0xff;
        let bad = NCryptVerifySignature(k, null(), h.as_ptr(), 32, sig.as_ptr(), n, 0) == 0;
        Ok((n as usize, good && !bad))
    }
}

/// Timed signing of SHA-256(msg), `iters` times. Returns per-call micros and the last signature.
fn sign_timed(k: NCRYPT_KEY_HANDLE, d: &[u8; 32], iters: usize) -> Res<(Vec<u128>, Vec<u8>)> {
    let mut n = 0u32;
    // SAFETY: size call once, then fixed-size buffer per signature.
    unsafe {
        st(
            "NCryptSignHash(size)",
            NCryptSignHash(k, null(), d.as_ptr(), 32, null_mut(), 0, &mut n, 0),
        )?;
        let mut times = Vec::with_capacity(iters);
        let mut sig = vec![0u8; n as usize];
        for _ in 0..iters {
            let mut m = 0u32;
            let t = Instant::now();
            let r = NCryptSignHash(k, null(), d.as_ptr(), 32, sig.as_mut_ptr(), n, &mut m, 0);
            times.push(us(t));
            st("NCryptSignHash", r)?;
            sig.truncate(m as usize);
        }
        Ok((times, sig))
    }
}

fn verify_handle(k: NCRYPT_KEY_HANDLE, d: &[u8; 32], sig: &[u8]) -> bool {
    // SAFETY: read-only buffers.
    unsafe {
        NCryptVerifySignature(k, null(), d.as_ptr(), 32, sig.as_ptr(), sig.len() as u32, 0) == 0
    }
}

/// Verify with the exported public key only (BCrypt, no KSP and no private key involved).
/// Returns (good verifies, tampered rejected, wrong digest rejected, verify micros).
fn verify_pub(
    pubblob: &[u8],
    d: &[u8; 32],
    other: &[u8; 32],
    sig: &[u8],
) -> Res<(bool, bool, bool, u128)> {
    let mut hk: BCRYPT_KEY_HANDLE = null_mut();
    // SAFETY: pseudo algorithm handle (Windows 10+); buffers outlive the calls; key destroyed below.
    unsafe {
        st(
            "BCryptImportKeyPair",
            BCryptImportKeyPair(
                BCRYPT_ECDSA_P256_ALG_HANDLE,
                null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                &mut hk,
                pubblob.as_ptr(),
                pubblob.len() as u32,
                0,
            ),
        )?;
        let v = |h: &[u8; 32], s: &[u8]| {
            BCryptVerifySignature(hk, null(), h.as_ptr(), 32, s.as_ptr(), s.len() as u32, 0) == 0
        };
        let t = Instant::now();
        let good = v(d, sig);
        let tv = us(t);
        let mut bad = sig.to_vec();
        bad[0] ^= 0xff;
        let tampered = !v(d, &bad);
        let wrong = !v(other, sig);
        BCryptDestroyKey(hk);
        Ok((good, tampered, wrong, tv))
    }
}

fn pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: NUL-terminated wide string owned by the NCrypt buffer, read before it is freed.
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// Names of the current user's keys in this provider (no NCRYPT_MACHINE_KEY_FLAG).
fn enum_names(p: NCRYPT_PROV_HANDLE) -> Res<Vec<String>> {
    let mut state: *mut c_void = null_mut();
    let mut names = Vec::new();
    // SAFETY: each NCryptKeyName and the enum state are freed with NCryptFreeBuffer.
    unsafe {
        loop {
            let mut kn: *mut NCryptKeyName = null_mut();
            let r = NCryptEnumKeys(p, null(), &mut kn, &mut state, NCRYPT_SILENT_FLAG);
            if r == NTE_NO_MORE_ITEMS {
                break;
            }
            if r != 0 {
                if !state.is_null() {
                    NCryptFreeBuffer(state);
                }
                return Err(("NCryptEnumKeys", r));
            }
            names.push(pwstr((*kn).pszName));
            NCryptFreeBuffer(kn as *mut c_void);
        }
        if !state.is_null() {
            NCryptFreeBuffer(state);
        }
    }
    Ok(names)
}

/// op = probe|inventory|create|sign|verify-pub|delete|all. The run script drives create/sign/delete as
/// separate processes so persistence across processes is exercised.
pub fn run(op: &str, provider: &str, key: &str, a: &Args) -> bool {
    let mut j = J::new();
    j.s("op", &format!("cng-{op}"))
        .s("provider", provider)
        .s("key_name", key);
    let fail = |j: &mut J, (f, r): (&str, i32)| {
        j.b("ok", false)
            .s("error", f)
            .s("status_hex", &hx(r))
            .emit();
        false
    };
    if op == "probe" {
        for (id, n) in [
            ("software", MS_KEY_STORAGE_PROVIDER),
            ("platform", MS_PLATFORM_CRYPTO_PROVIDER),
        ] {
            match open_provider(n) {
                Ok(h) => {
                    j.b(&format!("{id}_provider_open"), true);
                    // Attempt 3: Impl Type is not supported on key handles (attempt 2: 0x80090029),
                    // so read it from the provider handle.
                    match get_u32(h, NCRYPT_IMPL_TYPE_PROPERTY) {
                        Ok(v) => j.n(&format!("{id}_provider_impl_type"), v as i64),
                        Err((_, r)) => j.s(&format!("{id}_provider_impl_type_status"), &hx(r)),
                    };
                    if id == "platform" {
                        match get_wstr(h, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY) {
                            Ok(s) => j.s("platform_type", &s),
                            Err((_, r)) => j.s("platform_type_status", &hx(r)),
                        };
                    }
                    free(h)
                }
                Err((_, r)) => {
                    j.b(&format!("{id}_provider_open"), false)
                        .s(&format!("{id}_provider_status"), &hx(r));
                }
            }
        }
        j.b("ok", true).emit();
        return true;
    }
    if op == "verify-pub" {
        // No provider is opened: only the exported public key file and the signature file are used.
        let msg = a.get("--msg", "heimdall-x4-stores-sign-marker");
        let r: Res<()> = (|| {
            let pubblob =
                std::fs::read(a.get("--pub-in", "")).map_err(|_| ("read pub file", -1))?;
            let sig = std::fs::read(a.get("--sig-in", "")).map_err(|_| ("read sig file", -1))?;
            let d = sha256(msg.as_bytes())?;
            let other = sha256(b"heimdall-x4-stores-some-other-message")?;
            let (good, tampered, wrong, tv) = verify_pub(&pubblob, &d, &other, &sig)?;
            j.n("pub_blob_len", pubblob.len() as i64)
                .n("sig_len", sig.len() as i64)
                .b("pub_verify_ok", good)
                .b("pub_tampered_rejected", tampered)
                .b("pub_wrong_digest_rejected", wrong)
                .n("pub_verify_us", tv as i64);
            if !(good && tampered && wrong) {
                return Err(("verify-pub mismatch", -1));
            }
            Ok(())
        })();
        if let Err(e) = r {
            return fail(&mut j, e);
        }
        j.b("ok", true).emit();
        return true;
    }
    let t_prov = Instant::now();
    let prov = match open_provider(if provider == "platform" {
        MS_PLATFORM_CRYPTO_PROVIDER
    } else {
        MS_KEY_STORAGE_PROVIDER
    }) {
        Ok(p) => p,
        Err(e) => return fail(&mut j, e),
    };
    j.n("provider_open_us", us(t_prov) as i64);
    let steps: &[&str] = if op == "all" {
        &["create", "sign", "delete"]
    } else {
        &[op]
    };
    for s in steps {
        let r: Res<()> = (|| {
            match *s {
                "inventory" => {
                    let mut names = enum_names(prov)?;
                    names.sort();
                    let prefix = a.get("--prefix", "heimdall-m00-t04-x4-");
                    let ours: Vec<&String> =
                        names.iter().filter(|n| n.starts_with(&prefix)).collect();
                    let heimdall = names.iter().filter(|n| n.starts_with("heimdall")).count();
                    j.n("count", names.len() as i64)
                        .s("names_sha256", &hex(&sha256(names.join("\n").as_bytes())?))
                        .s("prefix", &prefix)
                        .n("prefix_count", ours.len() as i64)
                        .s(
                            "prefix_names",
                            &ours
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(";"),
                        )
                        .n("heimdall_prefixed_count", heimdall as i64);
                }
                "create" => {
                    let t = Instant::now();
                    let (k, set) = create_key(prov, key)?;
                    j.n("create_finalize_us", us(t) as i64)
                        .s("export_policy_set_status", &hx(set));
                    key_props(&mut j, k);
                    let pub_blob = export_public(k);
                    free(k);
                    let b = pub_blob?;
                    let le = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
                    j.b("created", true).n("pub_blob_len", b.len() as i64);
                    j.b(
                        "pub_magic_ok",
                        b.len() >= 8 && le(0) == 0x31534345 && le(4) == 32,
                    );
                    j.s("pub_blob_hex", &hex(&b));
                    let out = a.get("--pub-out", "");
                    if !out.is_empty() {
                        j.b("pub_written", std::fs::write(&out, &b).is_ok());
                    }
                }
                "sign" => {
                    let t = Instant::now();
                    let k = open_key(prov, key)?;
                    j.n("key_open_us", us(t) as i64);
                    key_props(&mut j, k);
                    let r = sign_verify(k);
                    let timed = (|| {
                        let msg = a.get("--msg", "heimdall-x4-stores-sign-marker");
                        let d = sha256(msg.as_bytes())?;
                        let (times, sig) = sign_timed(k, &d, a.iterations())?;
                        Ok::<_, (&'static str, i32)>((msg, d, times, sig))
                    })();
                    let (n, ok) = match r {
                        Ok(v) => v,
                        Err(e) => {
                            free(k);
                            return Err(e);
                        }
                    };
                    j.n("sig_len", n as i64)
                        .b("verify_ok_and_tamper_rejected", ok);
                    let (msg, d, times, sig) = match timed {
                        Ok(v) => v,
                        Err(e) => {
                            free(k);
                            return Err(e);
                        }
                    };
                    let hv = verify_handle(k, &d, &sig);
                    free(k);
                    j.s("msg", &msg)
                        .s("digest_hex", &hex(&d))
                        .stats("sign", &times)
                        .s("sig_hex", &hex(&sig))
                        .b("timed_sig_verifies_with_handle", hv);
                    let out = a.get("--sig-out", "");
                    if !out.is_empty() {
                        j.b("sig_written", std::fs::write(&out, &sig).is_ok());
                    }
                }
                "delete" => {
                    let k = open_key(prov, key)?;
                    // Attempt 3 fix: the Platform Crypto Provider rejects NCRYPT_SILENT_FLAG on
                    // NCryptDeleteKey with NTE_BAD_FLAGS (observed in attempt 2). On that status the
                    // handle is still open (not freed on failure), so retry once with dwFlags = 0.
                    // SAFETY: k is a live key handle; it is freed by a successful delete.
                    let r1 = unsafe { NCryptDeleteKey(k, NCRYPT_SILENT_FLAG) };
                    j.s("delete_silent_status", &hx(r1));
                    if r1 == NTE_BAD_FLAGS {
                        let r2 = unsafe { NCryptDeleteKey(k, 0) };
                        j.s("delete_flags0_status", &hx(r2));
                        if r2 != 0 {
                            free(k);
                        }
                        st("NCryptDeleteKey(0)", r2)?;
                    } else {
                        if r1 != 0 {
                            free(k);
                        }
                        st("NCryptDeleteKey", r1)?;
                    }
                    j.b("deleted", true);
                    let gone = matches!(open_key(prov, key), Err((_, r)) if r == NTE_BAD_KEYSET);
                    j.b("open_after_delete_is_bad_keyset", gone);
                }
                _ => return Err(("unknown op", -1)),
            }
            Ok(())
        })();
        if let Err(e) = r {
            free(prov);
            return fail(&mut j, e);
        }
    }
    free(prov);
    j.b("ok", true).emit();
    true
}
