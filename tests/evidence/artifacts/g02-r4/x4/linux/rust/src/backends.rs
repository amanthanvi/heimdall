use crate::Backend;

#[cfg(not(feature = "backends"))]
pub fn pick(_: &str) -> Option<(Box<dyn Backend>, &'static str)> {
    None // baseline build: identical skeleton, no platform backends
}

#[cfg(feature = "backends")]
pub fn pick(name: &str) -> Option<(Box<dyn Backend>, &'static str)> {
    match name {
        "secret-service" => Some((Box::new(Ss), "secret-service")),
        "keyctl" => Some((Box::new(Kc { user: false }), "keyctl-session")),
        "keyctl-user" => Some((Box::new(Kc { user: true }), "keyctl-user")),
        _ => None,
    }
}

// Secret Service via the secret-service crate (zbus, pure Rust crypto).
#[cfg(feature = "backends")]
struct Ss;
#[cfg(feature = "backends")]
mod ss {
    use secret_service::{EncryptionType, blocking::SecretService};
    use std::collections::HashMap;
    pub fn attrs(n: &str) -> HashMap<&str, &str> {
        HashMap::from([("application", "heimdall-x4"), ("name", n)])
    }
    pub fn svc() -> Result<SecretService<'static>, String> {
        SecretService::connect(EncryptionType::Dh).map_err(|e| e.to_string())
    }
}
#[cfg(feature = "backends")]
impl Backend for Ss {
    fn store(&self, n: &str, s: &[u8]) -> Result<(), String> {
        let svc = ss::svc()?;
        let c = svc.get_default_collection().map_err(|e| e.to_string())?;
        c.unlock().map_err(|e| e.to_string())?;
        c.create_item("heimdall-x4", ss::attrs(n), s, true, "text/plain")
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn read(&self, n: &str) -> Result<Vec<u8>, String> {
        let svc = ss::svc()?;
        let c = svc.get_default_collection().map_err(|e| e.to_string())?;
        let items = c.search_items(ss::attrs(n)).map_err(|e| e.to_string())?;
        items
            .first()
            .ok_or("not found")?
            .get_secret()
            .map_err(|e| e.to_string())
    }
    fn del(&self, n: &str) -> Result<(), String> {
        let svc = ss::svc()?;
        let c = svc.get_default_collection().map_err(|e| e.to_string())?;
        let items = c.search_items(ss::attrs(n)).map_err(|e| e.to_string())?;
        items
            .first()
            .ok_or("not found")?
            .delete()
            .map_err(|e| e.to_string())
    }
    fn gone(&self, n: &str) -> Result<bool, String> {
        let svc = ss::svc()?;
        let c = svc.get_default_collection().map_err(|e| e.to_string())?;
        Ok(c.search_items(ss::attrs(n))
            .map_err(|e| e.to_string())?
            .is_empty())
    }
}

// Kernel keyring via linux-keyutils (safe wrapper over raw syscalls; the crate
// itself contains the unsafe FFI). Same scopes and rationale as the Go spike:
// "session" = session keyring; "user" = per-UID user keyring linked into the
// session keyring so the process possesses (and can read) its own keys.
#[cfg(feature = "backends")]
struct Kc {
    user: bool,
}
#[cfg(feature = "backends")]
impl Kc {
    fn ring(&self) -> Result<linux_keyutils::KeyRing, String> {
        use linux_keyutils::{
            KeyRing,
            KeyRingIdentifier::{Session, User},
        };
        let e = |e: linux_keyutils::KeyError| format!("{e:?}");
        if !self.user {
            return KeyRing::from_special_id(Session, false).map_err(e);
        }
        let u = KeyRing::from_special_id(User, true).map_err(e)?;
        KeyRing::from_special_id(Session, false)
            .map_err(e)?
            .link_keyring(u)
            .map_err(e)?;
        Ok(u)
    }
}
#[cfg(feature = "backends")]
impl Backend for Kc {
    fn store(&self, n: &str, s: &[u8]) -> Result<(), String> {
        self.ring()?
            .add_key(n, s)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
    fn read(&self, n: &str) -> Result<Vec<u8>, String> {
        let k = self.ring()?.search(n).map_err(|e| format!("{e:?}"))?;
        k.read_to_vec().map_err(|e| format!("{e:?}"))
    }
    fn del(&self, n: &str) -> Result<(), String> {
        let r = self.ring()?;
        let k = r.search(n).map_err(|e| format!("{e:?}"))?;
        k.revoke().map_err(|e| format!("{e:?}"))?;
        r.unlink_key(k).map_err(|e| format!("{e:?}"))
    }
    fn gone(&self, n: &str) -> Result<bool, String> {
        use linux_keyutils::KeyError::{KeyDoesNotExist, KeyRevoked};
        match self.ring()?.search(n) {
            Err(KeyDoesNotExist | KeyRevoked) => Ok(true),
            Err(e) => Err(format!("{e:?}")),
            Ok(_) => Ok(false),
        }
    }
}
