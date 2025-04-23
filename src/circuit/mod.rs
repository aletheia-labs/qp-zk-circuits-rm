use amounts::{Amounts, AmountsTargets};
use nullifier::{Nullifier, NullifierTargets};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, ProverCircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
    },
};
use storage_proof::{StorageProof, StorageProofTargets};
use unspendable_account::{UnspendableAccount, UnspendableAccountTargets};

pub mod amounts;
pub mod nullifier;
pub mod storage_proof;
pub mod unspendable_account;

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type Digest = [F; 4];
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;

pub const SECRET_NUM_BYTES: usize = 32;
/// A unique salt used to differentiate this domain from others.
// TODO: Consider using an even more specific domain seperator.
pub const SALT: &[u8] = "wormhole".as_bytes();

pub trait CircuitFragment {
    type PrivateInputs;
    type Targets;

    fn circuit(builder: &mut CircuitBuilder<F, D>) -> Self::Targets;

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()>;
}

/// Converts a given slice into its field element representation.
pub fn slice_to_field_elements(input: &[u8]) -> Vec<F> {
    const BYTES_PER_ELEMENT: usize = 8;

    let mut field_elements: Vec<F> = Vec::new();
    for chunk in input.chunks(BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element
        let value = u64::from_le_bytes(bytes);
        let field_element = F::from_noncanonical_u64(value);
        field_elements.push(field_element);
    }

    field_elements
}

#[derive(Debug, Clone)]
pub struct CircuitTargets {
    pub amounts: AmountsTargets,
    pub nullifier: NullifierTargets,
    pub unspendable_account: UnspendableAccountTargets,
    pub storage_proof: StorageProofTargets,
}

impl CircuitTargets {
    fn new(
        amounts: AmountsTargets,
        nullifier: NullifierTargets,
        unspendable_account: UnspendableAccountTargets,
        storage_proof: StorageProofTargets,
    ) -> Self {
        Self {
            amounts,
            nullifier,
            unspendable_account,
            storage_proof,
        }
    }
}

pub struct WormholeCircuit {
    builder: CircuitBuilder<F, D>,
    targets: CircuitTargets,
}

impl Default for WormholeCircuit {
    fn default() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Setup circuits and their targets.
        let amounts = Amounts::circuit(&mut builder);
        let nullifier = Nullifier::circuit(&mut builder);
        let unspendable_account = UnspendableAccount::circuit(&mut builder);
        let storage_proof = StorageProof::circuit(&mut builder);
        let targets = CircuitTargets::new(amounts, nullifier, unspendable_account, storage_proof);

        Self { builder, targets }
    }
}

impl WormholeCircuit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn targets(&self) -> CircuitTargets {
        self.targets.clone()
    }

    pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
        self.builder.build_prover()
    }

    pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
        self.builder.build_verifier()
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::plonk::proof::ProofWithPublicInputs;

    use super::*;

    /// Convenince function for initializing a test circuit environment.
    pub fn setup_test_builder_and_witness() -> (CircuitBuilder<F, D>, PartialWitness<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let pw = PartialWitness::new();

        (builder, pw)
    }

    /// Convenince function for building and verifying a test function. The circuit is assumed to
    /// have been setup prior to calling this function.
    pub fn build_and_prove_test(
        builder: CircuitBuilder<F, D>,
        pw: PartialWitness<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let data = builder.build::<C>();
        data.prove(pw)
    }
}
