use anyhow::bail;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use wormhole_verifier::{ProofWithPublicInputs, WormholeVerifier};
use zk_circuits_common::circuit::{C, D, F};

use crate::{
    circuits::tree::{aggregate_to_tree, AggregatedProof},
    util::pad_with_dummy_proofs,
};

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator<const N: usize> {
    pub leaf_circuit_data: VerifierCircuitData<F, C, D>,
    pub proofs_buffer: Option<Vec<ProofWithPublicInputs<F, C, D>>>,
}

impl<const N: usize> Default for WormholeProofAggregator<N> {
    fn default() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        Self::new(config)
    }
}

impl<const N: usize> WormholeProofAggregator<N> {
    pub fn new(config: CircuitConfig) -> Self {
        let leaf_circuit_data = WormholeVerifier::new(config.clone(), None).circuit_data;
        let proofs_buffer = Some(Vec::with_capacity(N));

        Self {
            leaf_circuit_data,
            proofs_buffer,
        }
    }

    pub fn push_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        if let Some(proofs_buffer) = self.proofs_buffer.as_mut() {
            if proofs_buffer.len() >= N {
                bail!("tried to add proof when proof buffer is full")
            }
            proofs_buffer.push(proof);
        } else {
            self.proofs_buffer = Some(vec![proof]);
        }

        Ok(())
    }

    /// Aggregates `N` number of leaf proofs into an [`AggregatedProof`].
    pub fn aggregate(&mut self) -> anyhow::Result<AggregatedProof<F, C, D>> {
        let Some(proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        let padded_proofs = pad_with_dummy_proofs::<N>(proofs, &self.leaf_circuit_data.common)?;
        let root_proof = aggregate_to_tree(
            padded_proofs,
            &self.leaf_circuit_data.common,
            &self.leaf_circuit_data.verifier_only,
        )?;

        Ok(root_proof)
    }
}
