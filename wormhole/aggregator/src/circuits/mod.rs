pub mod flat;
pub mod tree;

#[cfg(not(feature = "no_zk"))]
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../../data/dummy_proof_zk.bin");
#[cfg(feature = "no_zk")]
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../../data/dummy_proof.bin");
