use amounts::Amounts;
use nullifier::{Nullifier, NullifierInputs};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs,
    },
};
use storage_proof::{StorageProof, StorageProofInputs};
use unspendable_account::{UnspendableAccount, UnspendableAccountInputs};

pub mod amounts;
mod nullifier;
mod storage_proof;
mod unspendable_account;

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

    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets;

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub struct WormholeProofPublicInputs {
    // Prevents double-claims (double hash of salt + txid + secret)
    pub nullifier: Nullifier,
    // Account the user wishes to withdraw to
    // exit_account: AccountId,
    pub amounts: Amounts,
    // Used to verify the transaction success event
    pub storage_root: [u8; 32],
    // The order that the tx was mined in, also referred to as `tx_id`
    pub extrinsic_index: u64,
}

impl WormholeProofPublicInputs {
    pub fn new(
        nullifier: Nullifier,
        amounts: Amounts,
        storage_root: [u8; 32],
        extrinsic_index: u64,
    ) -> Self {
        Self {
            nullifier,
            amounts,
            storage_root,
            extrinsic_index,
        }
    }
}

#[derive(Debug)]
pub struct WormholeProofPrivateInputs {
    /// Unspendable account
    pub unspendable_account: UnspendableAccount,
    /// Proves balance
    pub storage_proof: StorageProof,
    /// Secret value preimage of unspendable_address, this is also used in the nullifier computation
    pub unspendable_secret: &'static str,
}

impl WormholeProofPrivateInputs {
    pub fn new(
        unspendable_account: UnspendableAccount,
        storage_proof: StorageProof,
        unspendable_secret: &'static str,
    ) -> Self {
        Self {
            unspendable_account,
            storage_proof,
            unspendable_secret,
        }
    }
}

/// This zk-circuit verifies:
/// - Unspendable account is actually unspendable AccountId = H(H(salt+secret))
/// - The nullifier was computed correctly H(H('nullifier'+extrinsic_index+secret))
/// - A storage proof that the funding transaction resulted in a success event.
///   - Storage proof is a merkle-patricia-proof connecting the transfer success event to the storage-root.
///   - Implementation Notes For Substrate:
///     - Events are stored in the storage trie.
///     - Recent block headers and their storage roots are stored in current state and can be referenced by
///       block number, which should be sent along with the storage-root for O(1) lookup.
///     - Any recent block's storage-root can be used for the storage proof. If a block moves out of the recent-set
///       before the wormhole exit is included in a block, the wallet can recreate the storage-proof from a more recent block and resubmit it.
/// - The fee_amount + exit_amount = funding_tx_amount.
pub fn verify(
    public_inputs: WormholeProofPublicInputs,
    private_inputs: WormholeProofPrivateInputs,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    // Plonky2 circuit config setup:
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Setup all the circuits.
    let unspendable_account_targets = private_inputs.unspendable_account.circuit(&mut builder);
    let amounts_targets = public_inputs.amounts.circuit(&mut builder);
    let nullifier_targets = public_inputs.nullifier.circuit(&mut builder);
    let storage_proof_targets = private_inputs.storage_proof.circuit(&mut builder);

    let mut pw = PartialWitness::new();
    private_inputs.unspendable_account.fill_targets(
        &mut pw,
        unspendable_account_targets,
        UnspendableAccountInputs::new(private_inputs.unspendable_secret)?,
    )?;
    public_inputs
        .amounts
        .fill_targets(&mut pw, amounts_targets, ())?;
    public_inputs.nullifier.fill_targets(
        &mut pw,
        nullifier_targets,
        // TODO: Need to refactor inputs to take in preimages separately.
        NullifierInputs::new(private_inputs.unspendable_secret)?,
    )?;
    private_inputs.storage_proof.fill_targets(
        &mut pw,
        storage_proof_targets,
        StorageProofInputs {
            root_hash: public_inputs.storage_root,
        },
    )?;

    // Build the circuit.
    let data = builder.build::<C>();

    // Generate the proof.
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    Ok(proof)
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

#[cfg(test)]
pub mod tests {
    // use plonky2::field::types::PrimeField64;

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

    ///// An array containing all the values of the inputs that we expect to be exposed as public.
    ///// The format is as follows:
    ///// \[AccountId (Hash elements) | Amounts (3xF) | Nullifier (Hash elements) | TxId (8 bytes)\]
    //const EXPECTED_PUBLIC_INPUTS: [u64; 19] = [
    //    7457191426581024878,
    //    11405048483280340706,
    //    7057747067867402609,
    //    15727825555040390790,
    //    100,
    //    90,
    //    10,
    //    3057985780030117758,
    //    8797366881033976523,
    //    4328197692386296141,
    //    16319348266743790422,
    //    0,
    //    0,
    //    0,
    //    0,
    //    0,
    //    0,
    //    0,
    //    0,
    //];
    //
    //struct WormholeProofTestInputs {
    //    public_inputs: WormholeProofPublicInputs,
    //    private_inputs: WormholeProofPrivateInputs,
    //}
    //
    //impl Default for WormholeProofTestInputs {
    //    fn default() -> Self {
    //        let funding_tx_amount = 100;
    //        let exit_amount = 90;
    //        let fee_amount = 10;
    //        let extrinsic_index = 0;
    //
    //        let unspendable_secret = "secret";
    //
    //        let root_hash = [0u8; 32];
    //        let storage_proof = StorageProof::default();
    //
    //        Self {
    //            public_inputs: WormholeProofPublicInputs::new(
    //                Nullifier::new(unspendable_secret).unwrap(),
    //                Amounts::new(funding_tx_amount, exit_amount, fee_amount),
    //                root_hash,
    //                extrinsic_index,
    //            ),
    //            private_inputs: WormholeProofPrivateInputs::new(
    //                UnspendableAccount::new(unspendable_secret).unwrap(),
    //                storage_proof,
    //                unspendable_secret,
    //            ),
    //        }
    //    }
    //}
    //
    //#[test]
    //fn build_and_verify_proof() {
    //    let inputs = WormholeProofTestInputs::default();
    //    verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    //}
    //
    //#[test]
    //fn only_public_inputs_are_exposed() {
    //    let inputs = WormholeProofTestInputs::default();
    //    let proof = verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    //
    //    for (i, input) in proof.public_inputs.iter().enumerate() {
    //        assert_eq!(input.to_noncanonical_u64(), EXPECTED_PUBLIC_INPUTS[i]);
    //    }
    //}
    //
    //#[test]
    //#[should_panic]
    //fn build_and_verify_proof_wrong_unspendable_secret() {
    //    let mut inputs = WormholeProofTestInputs::default();
    //    inputs.private_inputs.unspendable_secret = "terces";
    //    verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    //}
}
