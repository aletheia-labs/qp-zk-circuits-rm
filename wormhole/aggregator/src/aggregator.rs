use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
};
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

use crate::{
    circuits::{
        flat::{FlatAggregator, FlatAggregatorTargets},
        tree::{aggregate_to_tree, AggregatedProof},
    },
    util::pad_with_dummy_proofs,
};

/// The method to use for aggregation proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationMethod {
    /// Aggregates `N` proofs into a new single, composite proof.
    Flat,
    /// Aggregates proofs recursively into a tree structure.
    Tree,
}

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator<const N: usize> {
    // TODO: Remove dependancy on flat aggregator.
    pub inner: FlatAggregator<N>,
    pub circuit_data: CircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: FlatAggregatorTargets<N>,
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
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // Setup inner aggregator and targets.
        let inner = FlatAggregator::new(config.clone());
        let targets = FlatAggregatorTargets::new(&mut builder, config);

        // Setup circuits.
        FlatAggregator::circuit(&targets, &mut builder);

        let circuit_data = builder.build();
        let partial_witness = PartialWitness::new();
        let proofs_buffer = Some(Vec::with_capacity(N));

        Self {
            inner,
            circuit_data,
            partial_witness,
            targets,
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

    // TODO: Unify aggregation.
    pub fn aggregate(&mut self) -> anyhow::Result<()> {
        let Some(proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        self.inner.set_proofs(proofs)?;
        self.inner
            .fill_targets(&mut self.partial_witness, self.targets.clone())?;

        Ok(())
    }

    pub fn aggregate_tree(&mut self) -> anyhow::Result<AggregatedProof<F, C, D>> {
        let Some(proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        let padded_proofs = pad_with_dummy_proofs::<N>(proofs, &self.circuit_data.common)?;
        let root_proof = aggregate_to_tree(
            padded_proofs,
            &self.circuit_data.common,
            &self.circuit_data.verifier_only,
        )?;

        Ok(root_proof)
    }

    /// Prove the circuit with commited values. It's necessary to call [`WormholeProofAggregator::aggregate`]
    /// before running this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not commited to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data.prove(self.partial_witness)
    }
}
