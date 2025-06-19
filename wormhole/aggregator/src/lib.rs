pub mod aggregator;
pub mod circuits;
mod util;

// TODO: Calculate number of proofs based on tree depth.
/// The maximum numbers of proofs to aggregate into a composite proof.
pub const DEFAULT_NUM_PROOFS_TO_AGGREGATE: usize = 2_usize.pow(3);
