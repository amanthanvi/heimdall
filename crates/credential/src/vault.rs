//! The key vault (ADR-0008 D1, D2; m03-plan U1 `vault::KeyVault`): K_env and K_verify
//! in a private `SecretKey` type (no `Clone`, `Debug`, `Display`, `Serialize`,
//! `Deserialize`; zeroized on drop; pages locked where the platform allows), handed
//! out only as opaque random 128-bit `VaultSlot` handles.
//!
//! U1 fills this module (`generate_ed25519`, `sign`, `destroy`, `contains`, and the
//! test-configuration `with_test_seed`); wave 0 freezes no item here.
