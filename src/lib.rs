use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{Hasher, PoseidonGoldilocksConfig},
    },
};

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;

// TODO: Correct constants.
pub const ACCOUNT_HASH_SIZE: usize = 16;
pub const SALT: &[u8] = "~wormhole~".as_bytes();

pub type AccountId = HashOut<F>;

pub struct WormholeProofPublicInputs {
    // Prevents double-claims (double hash of salt + txid + secret)
    // nullifier: [u8; 64],
    // Account the user wishes to withdraw to
    // exit_account: AccountId,
    /// The amount that a wormhole deposit adress was funded with
    funding_tx_amount: u64,
    /// Amount to be given to exit_account
    exit_amount: u64,
    /// Amount to be given to miner
    fee_amount: u64,
    // Used to verify the transaction success event
    // storage_root: [u8; 32],
    // The order that the tx was mined in
    // extrinsic_index: u64,
}

impl WormholeProofPublicInputs {
    pub fn new(funding_tx_amount: u64, exit_amount: u64, fee_amount: u64) -> Self {
        Self {
            funding_tx_amount,
            exit_amount,
            fee_amount,
        }
    }
}

pub struct WormholeProofPrivateInputs {
    // Event that resulted from funding the unspendable address
    // funding_event: Vec<u8>,
    /// Unspendable account
    unspendable_account: AccountId,
    // Proves balance
    // storage_proof: Vec<u8>,
    /// Secret value preimage of unspendable_address, this is also used in the nullifier computation
    unspendable_secret: Vec<u8>,
}

impl WormholeProofPrivateInputs {
    pub fn new(unspendable_account: AccountId, unspendable_secret: Vec<u8>) -> Self {
        Self {
            unspendable_account,
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
) -> anyhow::Result<()> {
    // Plonky2 circuit config setup:
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Calculate the preimage, we need to do this before setting up the circuits so that we know
    // the correct length.
    let preimage: Vec<F> = [SALT, &private_inputs.unspendable_secret]
        .concat()
        .iter()
        .map(|v| F::from_canonical_u8(*v))
        .collect();

    // FIXME: For debugging.
    println!("SALT: {}", String::from_utf8(SALT.to_vec())?);
    println!(
        "SECRET: {}",
        String::from_utf8(private_inputs.unspendable_secret)?
    );
    let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
    println!("HASH: {:?}", inner_hash);
    let double_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
    println!("DOUBLE HASH: {:?}", double_hash);

    // Setup all the circuits.
    let (unspendable_account, preimage_target) =
        unspendable_account_circuit(&mut builder, preimage.len());
    let (funding_tx_amount, exit_amount, fee_amount) = funding_amount_circuit(&mut builder);

    let mut pw = PartialWitness::new();

    // Unspendable account circuit values.
    pw.set_hash_target(unspendable_account, private_inputs.unspendable_account)?;
    for i in 0..preimage.len() {
        pw.set_target(preimage_target[i], preimage[i])?;
    }

    // Funding amount circuit values.
    pw.set_target(
        funding_tx_amount,
        F::from_canonical_u64(public_inputs.funding_tx_amount),
    )?;
    pw.set_target(
        exit_amount,
        F::from_canonical_u64(public_inputs.exit_amount),
    )?;
    pw.set_target(fee_amount, F::from_canonical_u64(public_inputs.fee_amount))?;

    // Build the circuit.
    let data = builder.build::<C>();

    // Generate the proof.
    let proof = data.prove(pw)?;

    println!(
        "FUNDING: {}\nEXIT: {}\nFEE: {}\n",
        proof.public_inputs[0], proof.public_inputs[1], proof.public_inputs[2]
    );

    data.verify(proof)?;

    Ok(())
}

/// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
fn unspendable_account_circuit(
    builder: &mut CircuitBuilder<F, D>,
    preimage_size: usize,
) -> (HashOutTarget, Vec<Target>) {
    let unspendable_account = builder.add_virtual_hash();
    let preimage = builder.add_virtual_targets(preimage_size);

    // Compute the `generated_account` by double-hashing the preimage (salt + secret).
    // NOTE: We assume that addresses are generated with Poseidon. Should double-check sometime.
    let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
    let generated_account =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

    // Assert that hashes are equal.
    for i in 0..4 {
        builder.connect(
            unspendable_account.elements[i],
            generated_account.elements[i],
        );
    }

    (unspendable_account, preimage)
}

/// Builds a circuit that asserts `funding_tx_amount = exit_amount + fee_amount`.
fn funding_amount_circuit(builder: &mut CircuitBuilder<F, D>) -> (Target, Target, Target) {
    let funding_tx_amount = builder.add_virtual_target();
    let exit_amount = builder.add_virtual_target();
    let fee_amount = builder.add_virtual_target();

    builder.register_public_input(funding_tx_amount);
    builder.register_public_input(exit_amount);
    builder.register_public_input(fee_amount);

    let sum = builder.add(exit_amount, fee_amount);
    builder.connect(sum, funding_tx_amount);

    (funding_tx_amount, exit_amount, fee_amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WormholeProofTestInputs {
        public_inputs: WormholeProofPublicInputs,
        private_inputs: WormholeProofPrivateInputs,
    }

    impl Default for WormholeProofTestInputs {
        fn default() -> Self {
            fn generate_unspendable_account() -> HashOut<F> {
                HashOut::from_vec(vec![
                    F::from_canonical_u64(4400158269619346328),
                    F::from_canonical_u64(7835876850004545748),
                    F::from_canonical_u64(9949762737399135748),
                    F::from_canonical_u64(17261303441366130639),
                ])
            }
            let funding_tx_amount = 100;
            let exit_amount = 90;
            let fee_amount = 10;

            let unspendable_account = generate_unspendable_account();
            let unspendable_secret = "~secret~".as_bytes().to_vec();
            Self {
                public_inputs: WormholeProofPublicInputs::new(
                    funding_tx_amount,
                    exit_amount,
                    fee_amount,
                ),
                private_inputs: WormholeProofPrivateInputs::new(
                    unspendable_account,
                    unspendable_secret,
                ),
            }
        }
    }

    #[test]
    fn build_and_verify_proof() {
        let inputs = WormholeProofTestInputs::default();
        verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    }

    #[test]
    #[should_panic]
    fn build_and_verify_proof_wrong_unspendable_secret() {
        let mut inputs = WormholeProofTestInputs::default();
        inputs.private_inputs.unspendable_secret = "~wrong-secret~".as_bytes().to_vec();

        verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    }

    #[test]
    #[should_panic]
    fn build_and_verify_proof_non_zero_sum_amounts() {
        let mut inputs = WormholeProofTestInputs::default();
        inputs.public_inputs.exit_amount = 200;

        verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    }
}
