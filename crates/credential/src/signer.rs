//! The managed signer (ADR-0008 D2 items 1–3, 3a; m03-plan U2 `ManagedSigner`): an
//! `ipc::signing::Signer` per endpoint kind (environment, binding, verification)
//! following the signing-gate protocol (purpose check, `SignatureAuthority::precheck`,
//! `admit`, `KeyVault::sign` under `signing_budget`, the permit returned as
//! `ipc::signing::PermitGuard`).
//!
//! U2 fills this module; wave 0 freezes no item here (the frozen pieces are
//! `ipc::signing` and the `app::ports::SignatureAuthority` port).
