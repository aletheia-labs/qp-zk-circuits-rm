use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_data::ProverCircuitData, proof::ProofWithPublicInputs},
};

use crate::{
    C, CircuitFragment, CircuitTargets, D, F, WormholeCircuit,
    amounts::Amounts,
    nullifier::{Nullifier, NullifierInputs},
    storage_proof::{StorageProof, StorageProofInputs},
    unspendable_account::{UnspendableAccount, UnspendableAccountInputs},
};

#[derive(Debug, Default)]
pub struct CircuitInputs<'a> {
    amounts: Amounts,
    nullifier: Nullifier,
    unspendable_account: UnspendableAccount,
    storage_proof: StorageProof,
    // TODO: Clean up input format.
    nullifier_preimage: &'a str,
    unspendable_account_preimage: &'a str,
    root_hash: [u8; 32],
}

#[derive(Debug)]
pub struct WormholeProver {
    circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<CircuitTargets>,
}

impl Default for WormholeProver {
    fn default() -> Self {
        let wormhole_circuit = WormholeCircuit::new();
        let partial_witness = PartialWitness::new();

        let targets = Some(wormhole_circuit.targets());
        let circuit_data = wormhole_circuit.builder.build_prover();

        Self {
            circuit_data,
            targets,
            partial_witness,
        }
    }
}

impl WormholeProver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Commits the provided [`CircuitInputs`] to the circuit by filling relevant targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has already commited to inputs previously.
    pub fn commit(mut self, circuit_inputs: CircuitInputs) -> anyhow::Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already commited to inputs");
        };

        let nullifier_inputs = NullifierInputs::new(circuit_inputs.nullifier_preimage)?;
        let unspendable_account_inputs =
            UnspendableAccountInputs::new(circuit_inputs.unspendable_account_preimage)?;

        circuit_inputs
            .amounts
            .fill_targets(&mut self.partial_witness, targets.amounts, ())?;
        circuit_inputs.nullifier.fill_targets(
            &mut self.partial_witness,
            targets.nullifier,
            nullifier_inputs,
        )?;
        circuit_inputs.unspendable_account.fill_targets(
            &mut self.partial_witness,
            targets.unspendable_account,
            unspendable_account_inputs,
        )?;
        circuit_inputs.storage_proof.fill_targets(
            &mut self.partial_witness,
            targets.storage_proof,
            StorageProofInputs::new(circuit_inputs.root_hash),
        )?;

        Ok(self)
    }

    /// Prove the circuit with commited values. It's necessary to call [`WormholeProver::commit`]
    /// before running this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not commited to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        if self.targets.is_some() {
            bail!("prover has not commited to any inputs")
        }
        self.circuit_data.prove(self.partial_witness)
    }
}

#[cfg(test)]
mod test {
    use super::{CircuitInputs, WormholeProver};

    #[test]
    fn commit_and_prove() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        prover.commit(inputs).unwrap().prove().unwrap();
    }
}
