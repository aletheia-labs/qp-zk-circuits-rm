pub mod aggregator;
pub mod circuits;

/// The maximum numbers of proofs to aggregate into a composite proof.
pub const DEFAULT_NUM_PROOFS_TO_AGGREGATE: usize = 2_usize.pow(4);
