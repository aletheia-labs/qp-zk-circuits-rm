//! Wormhole Zero-Knowledge Circuits
//!
//! # Modules
//!
//! - [`prover`]: Logic for generating zero-knowledge proofs for circuit statements.
//! - [`verifier`]: Logic for verifying proofs and public inputs.
pub(crate) mod circuit;
pub mod prover;
pub mod verifier;
