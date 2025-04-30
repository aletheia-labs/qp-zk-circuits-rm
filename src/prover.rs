use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_data::ProverCircuitData, proof::ProofWithPublicInputs},
};

use crate::circuit::{
    C, CircuitFragment, CircuitTargets, D, F, WormholeCircuit,
    amounts::Amounts,
    nullifier::{Nullifier, NullifierInputs},
    storage_proof::{StorageProof, StorageProofInputs},
    unspendable_account::{UnspendableAccount, UnspendableAccountInputs},
};

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    pub funding_tx_amount: u64,
    pub exit_amount: u64,
    pub fee_amount: u64,
    pub nullifier_preimage: Vec<u8>,
    pub unspendable_account_preimage: Vec<u8>,
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
    pub root_hash: [u8; 32],
}

/// A prover for the wormhole circuit.
///
/// # Example
///
/// Setup prover, commit inputs, and then generate the proof:
///
/// ```
/// use wormhole_circuit::prover::{WormholeProver, CircuitInputs};
///
/// # fn main() -> anyhow::Result<()> {
/// # let inputs = CircuitInputs::default();
/// let prover = WormholeProver::new();
/// let proof = prover.commit(inputs)?.prove()?;
/// # Ok(())
/// # }
/// ```
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
        let circuit_data = wormhole_circuit.build_prover();

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

        let amounts = Amounts::from(&circuit_inputs);
        let nullifier = Nullifier::from(&circuit_inputs);
        let unspendable_account = UnspendableAccount::from(&circuit_inputs);
        let storage_proof = StorageProof::from(&circuit_inputs);

        let nullifier_inputs = NullifierInputs::new(&circuit_inputs.nullifier_preimage)?;
        let unspendable_account_inputs =
            UnspendableAccountInputs::new(&circuit_inputs.unspendable_account_preimage)?;

        amounts.fill_targets(&mut self.partial_witness, targets.amounts, ())?;
        nullifier.fill_targets(
            &mut self.partial_witness,
            targets.nullifier,
            nullifier_inputs,
        )?;
        unspendable_account.fill_targets(
            &mut self.partial_witness,
            targets.unspendable_account,
            unspendable_account_inputs,
        )?;
        storage_proof.fill_targets(
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

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {

    use crate::circuit::{
        nullifier,
        storage_proof::test_helpers::{ROOT_HASH, default_proof},
        unspendable_account,
    };

    use super::CircuitInputs;

    impl Default for CircuitInputs {
        fn default() -> Self {
            let nullifier_preimage = hex::decode(nullifier::test_helpers::PREIMAGE).unwrap();
            let unspendable_account_preimage =
                hex::decode(unspendable_account::test_helpers::PREIMAGES[0]).unwrap();
            let root_hash: [u8; 32] = hex::decode(ROOT_HASH).unwrap().try_into().unwrap();
            Self {
                funding_tx_amount: 0,
                exit_amount: 0,
                fee_amount: 0,
                nullifier_preimage,
                unspendable_account_preimage,
                storage_proof: default_proof(),
                root_hash,
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{CircuitInputs, WormholeProver};

    #[test]
    fn commit_and_prove() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        prover.commit(inputs).unwrap().prove().unwrap();
    }
}
