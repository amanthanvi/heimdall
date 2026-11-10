//! The signer table (ADR-0008 D2 items 6–7, the credential-instance state machine on
//! the signer's side; m03-plan U2 `SignerTable`): key registration, certificate
//! installation against the published entry, materialization per binding, grant
//! destruction, and the identity listing of each endpoint kind (at most
//! [`MAX_LISTED`], comments `heimdall:<grant-short>`, never a label).
//!
//! **What each endpoint lists** (D2 item 2 as amended by F17 and reading R4/R3):
//!
//! | Endpoint | Lists |
//! |---|---|
//! | environment | the installed **certificates** of every materialized binding, for its materialized pairs only (at most one binding per pair) |
//! | binding `b` | the installed **certificates** of `b`'s grant |
//! | verification `op` | K_verify's plain public key **and** the certificate currently installed |
//!
//! **The plain K_env blob is never listed and never signed for** (F17, D2 item 4;
//! ADR-0008 §17.18 item 3, which keeps this for OpenSSH 9.5/9.6 too): the grant
//! endpoints list certificates only, and [`SignerTable::resolve`] never matches a
//! plain K_env blob. The verification endpoint lists K_verify (reading R3: 9.6p1
//! asks the agent for the plain key named by `IdentityFile K_verify.pub`), but its
//! userauth `key_blob` must still be the current certificate.
//!
//! **Persistence is not here.** This crate has no store edge (m03-plan §0.6), and no
//! `Operations` method writes `credential_instances` rows (question U2-Q1). The
//! effect driver (U10, ADR-0008 D6 item 0) persists the instance from what
//! [`SignerTable::register`] returns (`pending`, `subject_registered`), and its state
//! moves through [`instance_transition`], whose table is the D2 one (signer side).
//!
//! **D2 item 6's read transaction** (generation, tombstones, safe deadline) needs a
//! store read that no `Operations` method offers (question U2-Q2). It is the
//! [`InstallView`] the runtime supplies; without one every install is refused
//! ([`InstallRefusal::StoreViewUnavailable`]; switch [`INSTALL_STORE_VIEW_WIRED`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use async_trait::async_trait;
use heimdall_app::ports::{KeyRegistration, SignatureSubject, SignerEndpoint};
use heimdall_contract::ids::{
    AccountName, BindingId, DestinationId, GrantId, IssuanceId, OperationId,
};
use heimdall_domain::issuance::{CredentialState, IssuanceEntry, IssuanceState, principal_for};
use heimdall_domain::scope::AccessPair;
use ssh_key::certificate::{CertType, Certificate};
use ssh_key::{HashAlg, PublicKey};

use crate::cert::{CertRefusal, validate_installed};
use crate::purpose::{GrantCertificateError, GrantCertificates};
use crate::vault::{KeyVault, PublicKeyInfo, VaultError, VaultSlot};

/// The most identities any endpoint lists (`ipc::signing::MAX_IDENTITIES`).
pub const MAX_LISTED: usize = heimdall_ipc::signing::MAX_IDENTITIES;

/// How many characters of a grant ID's random part the listing comment carries
/// (`heimdall:<grant-short>`). The ID is random, never a label.
pub const GRANT_SHORT_CHARS: usize = 12;

/// The `permit-agent-forwarding` extension: a certificate carries it only when the
/// grant's scope has the `agent-forwarding` capability (ADR-0005 §3.4, the extension
/// profile of ADR-0008 D6 item 1), so the signer reads that capability from the
/// installed certificate it is asked to sign for (D2 item 5).
pub use heimdall_domain::issuance::EXTENSION_AGENT_FORWARDING;

/// ⟨U2-Q2⟩ Whether a production [`InstallView`] exists. `false` in wave 2: no
/// `Operations` method offers D2 item 6's read, so an installation without a view is
/// refused ([`InstallRefusal::StoreViewUnavailable`]). U10 (or the integrator) wires
/// one and flips this.
pub const INSTALL_STORE_VIEW_WIRED: bool = false;

/// How many certificates one verification endpoint accepts (ADR-0008 D5 §6.5: the
/// positive, then the negative, each installed just before its attempt).
pub const VERIFICATION_CERTIFICATES_PER_SESSION: usize = 2;

/// The negative verification principal's prefix (`hm:verify-negative:<32 hex>`).
pub const NEGATIVE_PRINCIPAL_PREFIX: &str = "hm:verify-negative:";

/// The longest validity a verification certificate may have (D5 §6.5: `valid_after`
/// = now − 60 s, `valid_before` ≤ now + 300 s).
pub const VERIFICATION_MAX_VALIDITY_SECS: u64 = 360;

// --- the credential-instance state machine (signer side) -------------------------

/// An event of the credential-instance state machine (ADR-0008 D2 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstanceEvent {
    /// Every pair's certificate published and installed.
    AllInstalled,
    /// A reservation was refused or voided before every pair was installed.
    ReservationFailed,
    /// The process exited before every pair was installed (found at the next start).
    ExitBeforeInstalled,
    /// The grant ended.
    GrantEnded,
    /// The process exited with the key installed (found at the next start).
    ProcessExit,
    /// The ADR-0005 §3.7 recovery rule holds: re-issue (a new instance follows).
    RecoveryHolds,
    /// The recovery rule fails.
    RecoveryFails,
}

/// A transition the D2 table does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("credential instance cannot move from {from:?} on {event:?}")]
pub struct InvalidInstanceTransition {
    /// The state.
    pub from: CredentialState,
    /// The event.
    pub event: InstanceEvent,
}

/// The ADR-0008 D2 credential-instance table, exactly: `pending → installed | destroyed`,
/// `installed → destroyed | lost`, `lost → destroyed` (with a new instance on
/// recovery). `destroyed` is final. Pure.
///
/// # Errors
/// [`InvalidInstanceTransition`] for every other pair.
pub fn instance_transition(
    from: CredentialState,
    event: InstanceEvent,
) -> Result<CredentialState, InvalidInstanceTransition> {
    use CredentialState as S;
    use InstanceEvent as E;
    match (from, event) {
        (S::Pending, E::AllInstalled) => Ok(S::Installed),
        (S::Pending, E::ReservationFailed | E::ExitBeforeInstalled | E::GrantEnded)
        | (S::Installed, E::GrantEnded)
        | (S::Lost, E::RecoveryHolds | E::RecoveryFails) => Ok(S::Destroyed),
        (S::Installed, E::ProcessExit) => Ok(S::Lost),
        _ => Err(InvalidInstanceTransition { from, event }),
    }
}

// --- refusals -------------------------------------------------------------------

/// Why a key could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegisterRefusal {
    /// The grant already has a live key in this table.
    #[error("the grant already has a registered key")]
    AlreadyRegistered,
    /// The slot is not in the vault, or its public key is not `pub_info`.
    #[error("the vault slot does not hold the registered key")]
    SlotMismatch,
    /// No pair given.
    #[error("no pair to register")]
    NoPairs,
    /// The vault failed (randomness, encoding).
    #[error("vault: {0}")]
    Vault(VaultError),
}

impl RegisterRefusal {
    /// The nonsecret code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            RegisterRefusal::AlreadyRegistered => "already_registered",
            RegisterRefusal::SlotMismatch => "slot_mismatch",
            RegisterRefusal::NoPairs => "no_pairs",
            RegisterRefusal::Vault(_) => "vault",
        }
    }
}

/// Why a certificate was not installed (ADR-0008 D2 item 6). The certificate is
/// discarded; its entry stays counted in the residual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InstallRefusal {
    /// No live key for the grant (never registered, or destroyed).
    #[error("no live key for the grant")]
    NoKey,
    /// The entry is not `published`.
    #[error("the issuance entry is not published")]
    NotPublished,
    /// The entry names another grant or pair, or the pair is not one the key was
    /// registered for.
    #[error("the issuance entry does not match the grant and pair")]
    EntryMismatch,
    /// The certificate's structure, CA, subject or bounds deviate (D6 item 2).
    #[error("certificate refused: {0}")]
    Certificate(CertRefusal),
    /// The pair already has an installed certificate.
    #[error("the pair already has a certificate")]
    AlreadyInstalled,
    /// The store view refused: stale generation, tombstone, or no safe deadline.
    #[error("the signer's view refused the installation: {0}")]
    View(&'static str),
    /// ⟨U2-Q2⟩ No [`InstallView`] is wired (fail closed).
    #[error("no store view for installation")]
    StoreViewUnavailable,
    /// A verification certificate is not acceptable (subject, principal, extensions,
    /// validity), or the session already holds its two certificates.
    #[error("verification certificate refused: {0}")]
    Verification(&'static str),
    /// The certificate could not be encoded.
    #[error("certificate encoding")]
    Encoding,
}

impl InstallRefusal {
    /// The nonsecret code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            InstallRefusal::NoKey => "no_key",
            InstallRefusal::NotPublished => "not_published",
            InstallRefusal::EntryMismatch => "entry_mismatch",
            InstallRefusal::Certificate(c) => c.code(),
            InstallRefusal::AlreadyInstalled => "already_installed",
            InstallRefusal::View(code) | InstallRefusal::Verification(code) => code,
            InstallRefusal::StoreViewUnavailable => "store_view_unavailable",
            InstallRefusal::Encoding => "encoding",
        }
    }
}

/// Why a binding could not be materialized into the environment listing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MaterializeRefusal {
    /// The binding is not attached to a grant ([`SignerTable::attach_binding`]).
    #[error("the binding is not attached to a grant")]
    UnknownBinding,
    /// The binding's grant has no installed certificate for a pair.
    #[error("no installed certificate for a pair")]
    NotInstalled(AccessPair),
    /// Another binding already holds a pair (D10 item 2: at most one binding per pair).
    #[error("another binding holds a pair")]
    PairHeld(AccessPair),
}

/// D2 item 6's read transaction: the signer's own view of the generation, the
/// tombstones and a safe deadline for `grant`, checked against the published `entry`
/// before its certificate is installed. Supplied by the runtime (U10) over the store.
#[async_trait]
pub trait InstallView: Send + Sync {
    /// `Ok` when the certificate may be installed now.
    ///
    /// # Errors
    /// [`InstallRefusal::View`] with a nonsecret code.
    async fn check(&self, grant: &GrantId, entry: &IssuanceEntry) -> Result<(), InstallRefusal>;
}

// --- table state ----------------------------------------------------------------

#[derive(Debug, Clone)]
struct Installed {
    blob: Vec<u8>,
    forwarding: bool,
    issuance: IssuanceId,
}

struct GrantKey {
    slot: VaultSlot,
    public: PublicKeyInfo,
    comment: String,
    pairs: BTreeSet<AccessPair>,
    certs: GrantCertificates,
    installed: BTreeMap<AccessPair, Installed>,
    state: CredentialState,
}

struct VerificationKey {
    slot: VaultSlot,
    public: PublicKeyInfo,
    comment: String,
    /// The positive certificate's pair (when installed), in a set of its own.
    certs: GrantCertificates,
    /// Installed blobs, in install order (at most two).
    installed: Vec<Vec<u8>>,
}

#[derive(Default)]
struct TableState {
    grants: HashMap<GrantId, GrantKey>,
    /// Binding endpoint → its grant.
    bindings: HashMap<BindingId, GrantId>,
    /// The environment listing: pair → the binding that holds it.
    materialized: BTreeMap<AccessPair, BindingId>,
    verifications: HashMap<OperationId, VerificationKey>,
}

struct TableInner {
    vault: Arc<KeyVault>,
    state: Mutex<TableState>,
    view: RwLock<Option<Arc<dyn InstallView>>>,
}

/// What a sign request's key resolves to on one endpoint ([`SignerTable::resolve`]).
#[derive(Clone)]
pub struct SignTarget {
    /// Whose key it is.
    pub subject: SignatureSubject,
    /// The vault slot.
    pub slot: VaultSlot,
    /// The key's `SHA256:` fingerprint (K_env or K_verify).
    pub key_fingerprint: String,
    /// The certificates the purpose check accepts on this endpoint.
    pub certs: GrantCertificates,
    /// The pairs whose installed certificate permits agent forwarding.
    pub forwarding: BTreeSet<AccessPair>,
    /// Whether the request named the plain key (only possible on a verification
    /// endpoint; reading R3).
    pub plain_requested: bool,
}

impl std::fmt::Debug for SignTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignTarget")
            .field("subject", &self.subject)
            .field("key_fingerprint", &self.key_fingerprint)
            .field("certificates", &self.certs.len())
            .finish_non_exhaustive()
    }
}

/// The signer's in-memory table of keys and certificates (ADR-0008 D2 items 6–7).
/// Cloning shares it. Holds the [`KeyVault`]; key material never leaves it.
#[derive(Clone)]
pub struct SignerTable {
    inner: Arc<TableInner>,
}

impl std::fmt::Debug for SignerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.lock();
        f.debug_struct("SignerTable")
            .field("grants", &s.grants.len())
            .field("bindings", &s.bindings.len())
            .field("materialized", &s.materialized.len())
            .field("verifications", &s.verifications.len())
            .finish()
    }
}

/// `heimdall:<grant-short>`: the first [`GRANT_SHORT_CHARS`] characters of the ID's
/// random part (never a label).
#[must_use]
pub fn grant_comment(grant: &GrantId) -> String {
    let id = grant.as_str();
    let random = id.split_once('_').map_or(id, |(_, r)| r);
    format!(
        "heimdall:{}",
        random.chars().take(GRANT_SHORT_CHARS).collect::<String>()
    )
}

/// `heimdall:v-<operation-short>` for a verification key.
#[must_use]
pub fn verification_comment(op: &OperationId) -> String {
    let id = op.as_str();
    let random = id.split_once('_').map_or(id, |(_, r)| r);
    format!(
        "heimdall:v-{}",
        random.chars().take(GRANT_SHORT_CHARS).collect::<String>()
    )
}

fn forwarding_of(cert: &Certificate) -> bool {
    cert.extensions().contains_key(EXTENSION_AGENT_FORWARDING)
}

/// The pair a positive verification principal names (`hm:<destination>:<account>`,
/// split at the last `:`; an account never contains one). `None` otherwise.
fn positive_pair(principal: &str) -> Option<AccessPair> {
    let rest = principal.strip_prefix("hm:")?;
    if principal.starts_with(NEGATIVE_PRINCIPAL_PREFIX) {
        return None;
    }
    let (d, a) = rest.rsplit_once(':')?;
    let pair = AccessPair {
        destination: DestinationId::parse(d).ok()?,
        account: AccountName::parse(a).ok()?,
    };
    (principal_for(&pair) == principal).then_some(pair)
}

fn negative_principal_ok(principal: &str) -> bool {
    principal
        .strip_prefix(NEGATIVE_PRINCIPAL_PREFIX)
        .is_some_and(|n| n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

impl SignerTable {
    /// An empty table over `vault`, with no [`InstallView`] (installs are refused
    /// until one is set; U2-Q2).
    #[must_use]
    pub fn new(vault: Arc<KeyVault>) -> SignerTable {
        SignerTable {
            inner: Arc::new(TableInner {
                vault,
                state: Mutex::new(TableState::default()),
                view: RwLock::new(None),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, TableState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The vault.
    #[must_use]
    pub fn vault(&self) -> &Arc<KeyVault> {
        &self.inner.vault
    }

    /// Set D2 item 6's store view (the runtime's; tests use a fixture).
    pub fn set_install_view(&self, view: Arc<dyn InstallView>) {
        *self
            .inner
            .view
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(view);
    }

    // --- registration -----------------------------------------------------------

    /// Register `grant`'s freshly generated K_env (`slot`, `pub_info`) for `pairs`:
    /// the instance is `pending`, `subject_registered` (ADR-0008 D2 table). Nothing is
    /// listed until a certificate is installed. The returned [`KeyRegistration`] is
    /// what the effect driver persists with the instance row (U2-Q1).
    ///
    /// # Errors
    /// [`RegisterRefusal`]; nothing is registered.
    pub fn register(
        &self,
        grant: &GrantId,
        slot: VaultSlot,
        pub_info: PublicKeyInfo,
        pairs: &[AccessPair],
    ) -> Result<KeyRegistration, RegisterRefusal> {
        if pairs.is_empty() {
            return Err(RegisterRefusal::NoPairs);
        }
        if self.inner.vault.public_key(&slot).as_ref() != Some(&pub_info) {
            return Err(RegisterRefusal::SlotMismatch);
        }
        let key = pub_info
            .public_key()
            .map_err(|_| RegisterRefusal::SlotMismatch)?;
        let certs = GrantCertificates::new(&key).map_err(|_| RegisterRefusal::SlotMismatch)?;
        let mut s = self.lock();
        if s.grants.contains_key(grant) {
            return Err(RegisterRefusal::AlreadyRegistered);
        }
        let registration = KeyRegistration {
            public_key: pub_info.openssh_line.clone(),
            fingerprint: pub_info.fingerprint.clone(),
            slot: slot.to_hex(),
        };
        s.grants.insert(
            grant.clone(),
            GrantKey {
                slot,
                public: pub_info,
                comment: grant_comment(grant),
                pairs: pairs.iter().cloned().collect(),
                certs,
                installed: BTreeMap::new(),
                state: CredentialState::Pending,
            },
        );
        Ok(registration)
    }

    /// Generate K_env in the vault and [`register`](Self::register) it. On any
    /// refusal the new key is destroyed at once.
    ///
    /// # Errors
    /// [`RegisterRefusal`].
    pub fn generate(
        &self,
        grant: &GrantId,
        pairs: &[AccessPair],
    ) -> Result<KeyRegistration, RegisterRefusal> {
        if pairs.is_empty() {
            return Err(RegisterRefusal::NoPairs);
        }
        let (slot, info) = self
            .inner
            .vault
            .generate_ed25519()
            .map_err(RegisterRefusal::Vault)?;
        self.register(grant, slot, info, pairs).inspect_err(|_| {
            self.inner.vault.destroy(&slot);
        })
    }

    /// The instance state the table holds for `grant` (`pending` or `installed`;
    /// `None` once destroyed or never registered).
    #[must_use]
    pub fn instance_state(&self, grant: &GrantId) -> Option<CredentialState> {
        self.lock().grants.get(grant).map(|k| k.state)
    }

    /// `grant`'s K_env public key, while it is live.
    #[must_use]
    pub fn public_key(&self, grant: &GrantId) -> Option<PublicKeyInfo> {
        self.lock().grants.get(grant).map(|k| k.public.clone())
    }

    /// `grant`'s vault slot, while it is live.
    #[must_use]
    pub fn slot(&self, grant: &GrantId) -> Option<VaultSlot> {
        self.lock().grants.get(grant).map(|k| k.slot)
    }

    /// The issuance entries of `grant`'s installed certificates, in pair order.
    #[must_use]
    pub fn installed_entries(&self, grant: &GrantId) -> Vec<IssuanceId> {
        self.lock()
            .grants
            .get(grant)
            .map(|k| k.installed.values().map(|i| i.issuance.clone()).collect())
            .unwrap_or_default()
    }

    // --- installation (D2 item 6) -----------------------------------------------

    /// Install `pair`'s certificate for `grant` after the signer's own check (ADR-0008
    /// D2 item 6): the entry is `published` and names this grant and pair (a pair the
    /// key was registered for); D6 item 2's structure check against the reserved
    /// bounds, with the subject equal to the grant's K_env and the CA the entry's;
    /// then the [`InstallView`]'s read (generation, tombstones, safe deadline). When
    /// every registered pair is installed the instance is `installed`. Any refusal
    /// discards the certificate; the entry stays counted.
    ///
    /// # Errors
    /// [`InstallRefusal`].
    pub async fn install(
        &self,
        grant: &GrantId,
        pair: &AccessPair,
        cert: &Certificate,
        entry: &IssuanceEntry,
    ) -> Result<(), InstallRefusal> {
        if entry.state != IssuanceState::Published {
            return Err(InstallRefusal::NotPublished);
        }
        if &entry.grant != grant || &entry.pair != pair {
            return Err(InstallRefusal::EntryMismatch);
        }
        let fingerprint = {
            let s = self.lock();
            let key = s.grants.get(grant).ok_or(InstallRefusal::NoKey)?;
            if !key.pairs.contains(pair) {
                return Err(InstallRefusal::EntryMismatch);
            }
            if key.installed.contains_key(pair) {
                return Err(InstallRefusal::AlreadyInstalled);
            }
            key.public.fingerprint.clone()
        };
        let ca = entry
            .bounds
            .ca_fingerprint
            .as_ref()
            .ok_or(InstallRefusal::Certificate(CertRefusal::NoReservedCa))?;
        validate_installed(cert, &entry.bounds, &fingerprint, ca)
            .map_err(InstallRefusal::Certificate)?;
        let view = self
            .inner
            .view
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(view) = view else {
            return Err(InstallRefusal::StoreViewUnavailable);
        };
        view.check(grant, entry).await?;
        let blob = cert.to_bytes().map_err(|_| InstallRefusal::Encoding)?;
        let mut s = self.lock();
        // Re-read: the key may have been destroyed while the view was read.
        let key = s.grants.get_mut(grant).ok_or(InstallRefusal::NoKey)?;
        if key.public.fingerprint != fingerprint {
            return Err(InstallRefusal::NoKey);
        }
        key.certs.add(pair.clone(), cert).map_err(|e| match e {
            GrantCertificateError::DuplicatePair => InstallRefusal::AlreadyInstalled,
            GrantCertificateError::SubjectNotGrantKey => {
                InstallRefusal::Certificate(CertRefusal::WrongSubject)
            }
            GrantCertificateError::PrincipalNotPair => {
                InstallRefusal::Certificate(CertRefusal::WrongPrincipal)
            }
            _ => InstallRefusal::Encoding,
        })?;
        key.installed.insert(
            pair.clone(),
            Installed {
                blob,
                forwarding: forwarding_of(cert),
                issuance: entry.id.clone(),
            },
        );
        if key.installed.len() == key.pairs.len() {
            key.state =
                instance_transition(key.state, InstanceEvent::AllInstalled).unwrap_or(key.state);
        }
        Ok(())
    }

    // --- bindings and the environment listing (D10) ------------------------------

    /// Attach binding `binding` (its endpoint) to `grant`: the binding endpoint lists
    /// and signs for that grant only. Re-attaching moves it.
    pub fn attach_binding(&self, binding: &BindingId, grant: &GrantId) {
        self.lock().bindings.insert(binding.clone(), grant.clone());
    }

    /// Detach a binding: its endpoint lists nothing and signs nothing; it is also
    /// unmaterialized.
    pub fn detach_binding(&self, binding: &BindingId) {
        let mut s = self.lock();
        s.bindings.remove(binding);
        s.materialized.retain(|_, b| b != binding);
    }

    /// The grant a binding is attached to.
    #[must_use]
    pub fn binding_grant(&self, binding: &BindingId) -> Option<GrantId> {
        self.lock().bindings.get(binding).cloned()
    }

    /// Materialize `binding` for `pairs` into the environment listing (ADR-0008 D10
    /// items 2–3): the environment endpoint then lists exactly its certificates for
    /// those pairs. At most one binding per pair; a pair this binding already holds
    /// is kept.
    ///
    /// # Errors
    /// [`MaterializeRefusal`]; nothing changes.
    pub fn materialize(
        &self,
        binding: &BindingId,
        pairs: &[AccessPair],
    ) -> Result<(), MaterializeRefusal> {
        let mut s = self.lock();
        let grant = s
            .bindings
            .get(binding)
            .cloned()
            .ok_or(MaterializeRefusal::UnknownBinding)?;
        let key = s
            .grants
            .get(&grant)
            .ok_or(MaterializeRefusal::UnknownBinding)?;
        for p in pairs {
            if !key.installed.contains_key(p) {
                return Err(MaterializeRefusal::NotInstalled(p.clone()));
            }
            if let Some(holder) = s.materialized.get(p)
                && holder != binding
            {
                return Err(MaterializeRefusal::PairHeld(p.clone()));
            }
        }
        for p in pairs {
            s.materialized.insert(p.clone(), binding.clone());
        }
        Ok(())
    }

    /// Remove `binding` from the environment listing (D10 item 2: the key is unlisted
    /// at once; the files go later, by generation).
    pub fn unmaterialize(&self, binding: &BindingId) {
        self.lock().materialized.retain(|_, b| b != binding);
    }

    /// The pairs `binding` holds in the environment listing.
    #[must_use]
    pub fn materialized_pairs(&self, binding: &BindingId) -> Vec<AccessPair> {
        self.lock()
            .materialized
            .iter()
            .filter(|(_, b)| *b == binding)
            .map(|(p, _)| p.clone())
            .collect()
    }

    // --- destruction (D2 item 7) ------------------------------------------------

    /// End `grant`'s key (ADR-0008 D2 item 7): unlist its identities from every
    /// endpoint (its materializations and binding attachments), drop its certificates
    /// and zeroize K_env in the vault. Called under the grant's gate held exclusively
    /// when the end is a narrowing (D2 item 3a). Returns whether a key was destroyed.
    /// Idempotent.
    pub fn destroy_grant(&self, grant: &GrantId) -> bool {
        let removed = {
            let mut s = self.lock();
            let removed = s.grants.remove(grant);
            let bindings: BTreeSet<BindingId> = s
                .bindings
                .iter()
                .filter(|(_, g)| *g == grant)
                .map(|(b, _)| b.clone())
                .collect();
            s.materialized.retain(|_, b| !bindings.contains(b));
            s.bindings.retain(|_, g| g != grant);
            removed
        };
        match removed {
            Some(key) => {
                self.inner.vault.destroy(&key.slot);
                drop(key);
                true
            }
            None => false,
        }
    }

    // --- verification keys (D5 §6.5) --------------------------------------------

    /// Generate `op`'s K_verify and register it for its verification endpoint.
    ///
    /// # Errors
    /// [`RegisterRefusal`].
    pub fn register_verification(
        &self,
        op: &OperationId,
    ) -> Result<PublicKeyInfo, RegisterRefusal> {
        let (slot, info) = self
            .inner
            .vault
            .generate_ed25519()
            .map_err(RegisterRefusal::Vault)?;
        let refuse = |e| {
            self.inner.vault.destroy(&slot);
            e
        };
        let key = info
            .public_key()
            .map_err(|_| refuse(RegisterRefusal::SlotMismatch))?;
        let certs =
            GrantCertificates::new(&key).map_err(|_| refuse(RegisterRefusal::SlotMismatch))?;
        let mut s = self.lock();
        if s.verifications.contains_key(op) {
            drop(s);
            return Err(refuse(RegisterRefusal::AlreadyRegistered));
        }
        s.verifications.insert(
            op.clone(),
            VerificationKey {
                slot,
                public: info.clone(),
                comment: verification_comment(op),
                certs,
                installed: Vec::new(),
            },
        );
        Ok(info)
    }

    /// Install a published verification certificate on `op`'s endpoint (the signer's
    /// check of ADR-0008 D2 item 6 for a verification: D5 §6.5 item 2's shape). The
    /// session accepts [`VERIFICATION_CERTIFICATES_PER_SESSION`] certificates, the
    /// positive then the negative, each just before its attempt; the latest is the
    /// one listed. Checked: a user certificate signed by its own signature key; the
    /// subject is K_verify; exactly one principal, `hm:<destination>:<account>` or
    /// `hm:verify-negative:<32 hex>`; no critical option and no extension; a validity
    /// of at most [`VERIFICATION_MAX_VALIDITY_SECS`]. Only a positive certificate can
    /// ever be signed for: the negative one is listed (so a server that wrongly
    /// accepts it shows up as a sign request) and every signature for it is refused.
    ///
    /// # Errors
    /// [`InstallRefusal`]; the certificate is discarded.
    pub fn install_verification(
        &self,
        op: &OperationId,
        cert: &Certificate,
    ) -> Result<(), InstallRefusal> {
        let mut s = self.lock();
        let key = s.verifications.get_mut(op).ok_or(InstallRefusal::NoKey)?;
        if key.installed.len() >= VERIFICATION_CERTIFICATES_PER_SESSION {
            return Err(InstallRefusal::Verification("session_full"));
        }
        if cert.cert_type() != CertType::User {
            return Err(InstallRefusal::Verification("not_user_certificate"));
        }
        if cert.verify_signature().is_err() {
            return Err(InstallRefusal::Certificate(CertRefusal::BadSignature));
        }
        if cert.public_key().fingerprint(HashAlg::Sha256).to_string() != key.public.fingerprint {
            return Err(InstallRefusal::Certificate(CertRefusal::WrongSubject));
        }
        if !cert.critical_options().is_empty() {
            return Err(InstallRefusal::Certificate(CertRefusal::CriticalOption));
        }
        if !cert.extensions().is_empty() {
            return Err(InstallRefusal::Certificate(
                CertRefusal::ExtensionOutsideReserved,
            ));
        }
        if cert.valid_before() <= cert.valid_after()
            || cert.valid_before() - cert.valid_after() > VERIFICATION_MAX_VALIDITY_SECS
        {
            return Err(InstallRefusal::Verification("validity"));
        }
        let [principal] = cert.valid_principals() else {
            return Err(InstallRefusal::Certificate(CertRefusal::PrincipalCount {
                count: cert.valid_principals().len(),
            }));
        };
        let blob = cert.to_bytes().map_err(|_| InstallRefusal::Encoding)?;
        if key.installed.contains(&blob) {
            return Err(InstallRefusal::AlreadyInstalled);
        }
        if let Some(pair) = positive_pair(principal) {
            key.certs
                .add(pair, cert)
                .map_err(|_| InstallRefusal::Verification("second_positive"))?;
        } else if !negative_principal_ok(principal) {
            return Err(InstallRefusal::Certificate(CertRefusal::WrongPrincipal));
        }
        key.installed.push(blob);
        Ok(())
    }

    /// `op`'s K_verify public key, while its endpoint lives.
    #[must_use]
    pub fn verification_key(&self, op: &OperationId) -> Option<PublicKeyInfo> {
        self.lock().verifications.get(op).map(|k| k.public.clone())
    }

    /// Zeroize `op`'s K_verify and forget its certificates (the verification
    /// session's end). Idempotent.
    pub fn destroy_verification(&self, op: &OperationId) -> bool {
        let removed = self.lock().verifications.remove(op);
        match removed {
            Some(key) => {
                self.inner.vault.destroy(&key.slot);
                true
            }
            None => false,
        }
    }

    // --- listing and resolution ---------------------------------------------------

    /// The identities `endpoint` lists, at most [`MAX_LISTED`], comments
    /// `heimdall:<grant-short>` (module docs for what each kind lists).
    #[must_use]
    pub fn list(&self, endpoint: &SignerEndpoint) -> Vec<(Vec<u8>, String)> {
        let s = self.lock();
        let mut out: Vec<(Vec<u8>, String)> = Vec::new();
        match endpoint {
            SignerEndpoint::Environment => {
                for (pair, binding) in &s.materialized {
                    let Some(key) = s.bindings.get(binding).and_then(|g| s.grants.get(g)) else {
                        continue;
                    };
                    if let Some(i) = key.installed.get(pair) {
                        out.push((i.blob.clone(), key.comment.clone()));
                    }
                }
            }
            SignerEndpoint::Binding(b) => {
                if let Some(key) = s.bindings.get(b).and_then(|g| s.grants.get(g)) {
                    for i in key.installed.values() {
                        out.push((i.blob.clone(), key.comment.clone()));
                    }
                }
            }
            SignerEndpoint::Verification(op) => {
                if let Some(key) = s.verifications.get(op) {
                    out.push((key.public.blob.clone(), key.comment.clone()));
                    if let Some(current) = key.installed.last() {
                        out.push((current.clone(), key.comment.clone()));
                    }
                }
            }
            _ => {}
        }
        out.truncate(MAX_LISTED);
        out
    }

    /// Resolve the key a sign request names on `endpoint` (`ipc`'s `key_blob`): a
    /// certificate this endpoint lists, or, on a verification endpoint only, the
    /// plain K_verify. A plain K_env blob, an unlisted certificate, or another
    /// endpoint's key resolves to `None` (refused before any authorization).
    #[must_use]
    pub fn resolve(&self, endpoint: &SignerEndpoint, key_blob: &[u8]) -> Option<SignTarget> {
        let s = self.lock();
        let grant_target = |grant: &GrantId, key: &GrantKey| SignTarget {
            subject: SignatureSubject::Grant(grant.clone()),
            slot: key.slot,
            key_fingerprint: key.public.fingerprint.clone(),
            certs: key.certs.clone(),
            forwarding: key
                .installed
                .iter()
                .filter(|(_, i)| i.forwarding)
                .map(|(p, _)| p.clone())
                .collect(),
            plain_requested: false,
        };
        match endpoint {
            SignerEndpoint::Environment => s.materialized.iter().find_map(|(pair, binding)| {
                let grant = s.bindings.get(binding)?;
                let key = s.grants.get(grant)?;
                (key.installed.get(pair)?.blob == key_blob).then(|| grant_target(grant, key))
            }),
            SignerEndpoint::Binding(b) => {
                let grant = s.bindings.get(b)?;
                let key = s.grants.get(grant)?;
                key.installed
                    .values()
                    .any(|i| i.blob == key_blob)
                    .then(|| grant_target(grant, key))
            }
            SignerEndpoint::Verification(op) => {
                let key = s.verifications.get(op)?;
                let plain = key.public.blob == key_blob;
                let current = key.installed.last().is_some_and(|c| c == key_blob);
                (plain || current).then(|| SignTarget {
                    subject: SignatureSubject::Verification(op.clone()),
                    slot: key.slot,
                    key_fingerprint: key.public.fingerprint.clone(),
                    certs: key.certs.clone(),
                    forwarding: BTreeSet::new(),
                    plain_requested: plain,
                })
            }
            _ => None,
        }
    }

    /// The certificate currently listed on `op`'s verification endpoint.
    #[must_use]
    pub fn current_verification_certificate(&self, op: &OperationId) -> Option<Vec<u8>> {
        self.lock()
            .verifications
            .get(op)
            .and_then(|k| k.installed.last().cloned())
    }

    /// Whether `key` (a K_env or K_verify public key) is still live in this table and
    /// its vault.
    #[must_use]
    pub fn holds_key(&self, key: &PublicKey) -> bool {
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let s = self.lock();
        s.grants
            .values()
            .map(|k| (&k.public, k.slot))
            .chain(s.verifications.values().map(|k| (&k.public, k.slot)))
            .any(|(p, slot)| p.fingerprint == fp && self.inner.vault.contains(&slot))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn instance_table_is_exactly_d2() {
        use CredentialState as S;
        use InstanceEvent as E;
        let states = [S::Pending, S::Installed, S::Destroyed, S::Lost];
        let events = [
            E::AllInstalled,
            E::ReservationFailed,
            E::ExitBeforeInstalled,
            E::GrantEnded,
            E::ProcessExit,
            E::RecoveryHolds,
            E::RecoveryFails,
        ];
        let allowed: &[(S, E, S)] = &[
            (S::Pending, E::AllInstalled, S::Installed),
            (S::Pending, E::ReservationFailed, S::Destroyed),
            (S::Pending, E::ExitBeforeInstalled, S::Destroyed),
            (S::Pending, E::GrantEnded, S::Destroyed),
            (S::Installed, E::GrantEnded, S::Destroyed),
            (S::Installed, E::ProcessExit, S::Lost),
            (S::Lost, E::RecoveryHolds, S::Destroyed),
            (S::Lost, E::RecoveryFails, S::Destroyed),
        ];
        for from in states {
            for event in events {
                let want = allowed
                    .iter()
                    .find(|(f, e, _)| *f == from && *e == event)
                    .map(|(_, _, t)| *t);
                assert_eq!(
                    instance_transition(from, event).ok(),
                    want,
                    "{from:?} {event:?}"
                );
            }
        }
    }

    #[test]
    fn comments_are_the_id_prefix_never_a_label() {
        let g = GrantId::from_random_bytes([0xab; 16]);
        assert_eq!(grant_comment(&g), "heimdall:abababababab");
        let op = OperationId::from_random_bytes([0x01; 16]);
        assert_eq!(verification_comment(&op), "heimdall:v-010101010101");
    }

    #[test]
    fn positive_and_negative_principals() {
        let p = positive_pair("hm:h1:deploy").unwrap();
        assert_eq!(p.destination.as_str(), "h1");
        assert_eq!(p.account.as_str(), "deploy");
        assert!(positive_pair("hm:verify-negative:0123").is_none());
        assert!(positive_pair("other:h1:deploy").is_none());
        assert!(negative_principal_ok(&format!(
            "{NEGATIVE_PRINCIPAL_PREFIX}{}",
            "a".repeat(32)
        )));
        assert!(!negative_principal_ok(&format!(
            "{NEGATIVE_PRINCIPAL_PREFIX}{}",
            "A".repeat(32)
        )));
        assert!(!negative_principal_ok(NEGATIVE_PRINCIPAL_PREFIX));
    }
}
