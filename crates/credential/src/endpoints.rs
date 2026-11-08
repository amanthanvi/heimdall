//! The signing endpoints (ADR-0008 D2; m03-plan U2 `EndpointRegistry`): the
//! environment endpoint, generation-tagged binding endpoints, and per-operation
//! verification endpoints implementing `app::ports::VerificationEndpoints` (dropping
//! a `VerificationSession` zeroizes K_verify and removes the endpoint).
//!
//! U2 fills this module; wave 0 freezes no item here.
