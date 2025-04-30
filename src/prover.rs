//! Prover logic for the Wormhole circuit.
//!
//! This module provides the [`WormholeProver`] type, which allows committing inputs to the circuit
//! and generating a zero-knowledge proof using those inputs.
//!
//! The typical usage flow involves:
//! 1. Initializing the prover (e.g., via [`WormholeProver::default`] or [`WormholeProver::new`]).
//! 2. Creating user inputs with [`CircuitInputs`].
//! 3. Committing user inputs using [`WormholeProver::commit`].
//! 4. Generating a proof using [`WormholeProver::prove`].
//!
//! # Example
//!
//! ```
//! use wormhole_circuit::prover::{WormholeProver, CircuitInputs};
//!
//! # fn main() -> anyhow::Result<()> {
//! # let inputs = CircuitInputs::default();
//! let prover = WormholeProver::new();
//! let proof = prover.commit(&inputs)?.prove()?;
//! # Ok(())
//! # }
//! ```
use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_data::ProverCircuitData, proof::ProofWithPublicInputs},
};

use crate::circuit::{
    C, CircuitFragment, CircuitTargets, D, F, WormholeCircuit,
    amounts::Amounts,
    exit_account::ExitAccount,
    nullifier::{Nullifier, NullifierInputs},
    storage_proof::{StorageProof, StorageProofInputs},
    unspendable_account::{UnspendableAccount, UnspendableAccountInputs},
};

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    /// The amount sent in the transaction.
    pub funding_tx_amount: u64,
    /// Amount to be withdrawn.
    pub exit_amount: u64,
    /// The fee for the transaction.
    pub fee_amount: u64,
    /// Raw bytes of the nullifier preimage, used to prevent double spends.
    pub nullifier_preimage: Vec<u8>,
    /// Raw bytes of the unspendable account preimage.
    pub unspendable_account_preimage: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
    /// The root hash of the storage trie.
    pub root_hash: [u8; 32],
    /// The address of the account to pay out to.
    pub exit_account: [u8; 32],
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
/// let proof = prover.commit(&inputs)?.prove()?;
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
            partial_witness,
            targets,
        }
    }
}

impl WormholeProver {
    /// Creates a new [`WormholeProver`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Commits the provided [`CircuitInputs`] to the circuit by filling relevant targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has already commited to inputs previously.
    pub fn commit(mut self, circuit_inputs: &CircuitInputs) -> anyhow::Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already commited to inputs");
        };

        let amounts = Amounts::from(circuit_inputs);
        let nullifier = Nullifier::from(circuit_inputs);
        let unspendable_account = UnspendableAccount::from(circuit_inputs);
        let storage_proof = StorageProof::from(circuit_inputs);
        let exit_account = ExitAccount::from(circuit_inputs);

        let nullifier_inputs = NullifierInputs::new(&circuit_inputs.nullifier_preimage);
        let unspendable_account_inputs =
            UnspendableAccountInputs::new(&circuit_inputs.unspendable_account_preimage);

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
        exit_account.fill_targets(&mut self.partial_witness, targets.exit_account, ())?;

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
mod test_helpers {
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
                exit_account: [0u8; 32],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CircuitInputs, WormholeProver};

    #[test]
    fn commit_and_prove() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        prover.commit(&inputs).unwrap().prove().unwrap();
    }
}
