pub mod aggregator;
pub mod circuits;
mod util;

/// The maximum numbers of proofs to aggregate into a composite proof.
pub const DEFAULT_NUM_PROOFS_TO_AGGREGATE: usize = TREE_BRANCHING_FACTOR.pow(TREE_DEPTH);

/// The tree branching factor.
pub const TREE_BRANCHING_FACTOR: usize = 2;

/// The depth of the tree of the aggregated proof.
pub const TREE_DEPTH: u32 = 3;
