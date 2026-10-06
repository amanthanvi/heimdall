use crate::{J, wide};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::*;

type Res<T> = Result<T, (&'static str, i32)>;

fn st(f: &'static str, r: i32) -> Res<()> {
    if r == 0 { Ok(()) } else { Err((f, r)) }
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

fn create_key(p: NCRYPT_PROV_HANDLE, name: &str) -> Res<NCRYPT_KEY_HANDLE> {
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
        NCryptSetProperty(
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
    }
    Ok(k)
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

/// op = probe|create|sign|delete|all. The run script drives create/sign/delete as separate
/// processes so persistence across processes is exercised.
pub fn run(op: &str, provider: &str, key: &str) -> bool {
    let mut j = J::new();
    j.s("op", &format!("cng-{op}"))
        .s("provider", provider)
        .s("key_name", key);
    let fail = |j: &mut J, (f, r): (&str, i32)| {
        j.b("ok", false)
            .s("error", f)
            .s("status_hex", &format!("0x{:08X}", r as u32))
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
                    free(h)
                }
                Err((_, r)) => {
                    j.b(&format!("{id}_provider_open"), false).s(
                        &format!("{id}_provider_status"),
                        &format!("0x{:08X}", r as u32),
                    );
                }
            }
        }
        j.b("ok", true).emit();
        return true;
    }
    let prov = match open_provider(if provider == "platform" {
        MS_PLATFORM_CRYPTO_PROVIDER
    } else {
        MS_KEY_STORAGE_PROVIDER
    }) {
        Ok(p) => p,
        Err(e) => return fail(&mut j, e),
    };
    let steps: &[&str] = if op == "all" {
        &["create", "sign", "delete"]
    } else {
        &[op]
    };
    for s in steps {
        let r: Res<()> = (|| {
            match *s {
                "create" => {
                    let k = create_key(prov, key)?;
                    let pub_blob = export_public(k);
                    free(k);
                    let b = pub_blob?;
                    let le = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
                    j.b("created", true).n("pub_blob_len", b.len() as i64);
                    j.b(
                        "pub_magic_ok",
                        b.len() >= 8 && le(0) == 0x31534345 && le(4) == 32,
                    );
                }
                "sign" => {
                    let k = open_key(prov, key)?;
                    let r = sign_verify(k);
                    free(k);
                    let (n, ok) = r?;
                    j.n("sig_len", n as i64)
                        .b("verify_ok_and_tamper_rejected", ok);
                }
                "delete" => {
                    let k = open_key(prov, key)?;
                    st("NCryptDeleteKey", unsafe {
                        NCryptDeleteKey(k, NCRYPT_SILENT_FLAG)
                    })?; // frees the handle
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
