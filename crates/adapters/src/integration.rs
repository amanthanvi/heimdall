//! The consumer integration `prepare` materializes (m02-plan U6; ADR-0007 §7, §8):
//! `ConsumerIntegration.environment` with `SSH_AUTH_SOCK` only when every pair uses
//! one endpoint, `executables`, `overrides`, and `pairs` with each pair's
//! interaction profile and the identity selection from `ProjectionWriter::observe`.
//! U6 writes this module; the wave-0 skeleton declares no function here.
