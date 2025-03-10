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
        proof::ProofWithPublicInputs,
    },
};

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type Digest = [F; 4];
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;

// TODO: Correct constants.
pub const ACCOUNT_HASH_SIZE: usize = 16;
pub const SALT: &[u8] = "wormhole".as_bytes();

pub type AccountId = Digest;

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
pub struct UnspendableAccount {
    account_id: AccountId,
}

impl UnspendableAccount {
    pub fn new(secret: &str) -> Self {
        // First, convert the secret to its bytes representation.
        let secret = string_to_padded_32_byte_array(secret);

        // Calculate the preimage by concatanating [`SALT`] and the secret value.
        let preimage: Vec<F> = [SALT, &secret]
            .concat()
            .iter()
            .map(|v| F::from_canonical_u8(*v))
            .collect();

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let account_id = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { account_id }
    }
}

pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    salt: Vec<Target>,
    secret: Vec<Target>,
}

pub struct UnspendableAccountInputs {
    salt: &'static [u8],
    secret: [u8; 32],
}

impl CircuitFragment for UnspendableAccount {
    type PrivateInputs = UnspendableAccountInputs;
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let account_id = builder.add_virtual_hash();
        let salt = builder.add_virtual_targets(8);
        let secret = builder.add_virtual_targets(32);

        let mut preimage = Vec::with_capacity(salt.len() + secret.len());
        preimage.extend(salt.clone());
        preimage.extend(secret.clone());

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        for i in 0..4 {
            builder.connect(account_id.elements[i], generated_account.elements[i]);
        }

        UnspendableAccountTargets {
            account_id,
            salt,
            secret,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, HashOut::from_partial(&self.account_id))?;
        for (i, byte) in inputs.salt.iter().enumerate() {
            pw.set_target(targets.salt[i], F::from_canonical_u8(*byte))?;
        }
        for (i, byte) in inputs.secret.iter().enumerate() {
            pw.set_target(targets.secret[i], F::from_canonical_u8(*byte))?;
        }

        Ok(())
    }
}

pub struct Amounts {
    /// The amount that a wormhole deposit adress was funded with
    funding_tx_amount: u64,
    /// Amount to be given to exit_account
    exit_amount: u64,
    /// Amount to be given to miner
    fee_amount: u64,
}

impl Amounts {
    pub fn new(funding_tx_amount: u64, exit_amount: u64, fee_amount: u64) -> Self {
        Self {
            funding_tx_amount,
            exit_amount,
            fee_amount,
        }
    }
}

pub struct AmountsTargets {
    funding_tx_amount: Target,
    exit_amount: Target,
    fee_amount: Target,
}

impl CircuitFragment for Amounts {
    type PrivateInputs = ();
    type Targets = AmountsTargets;

    /// Builds a circuit that asserts `funding_tx_amount = exit_amount + fee_amount`.
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let funding_tx_amount = builder.add_virtual_target();
        let exit_amount = builder.add_virtual_target();
        let fee_amount = builder.add_virtual_target();

        builder.register_public_input(funding_tx_amount);
        builder.register_public_input(exit_amount);
        builder.register_public_input(fee_amount);

        let sum = builder.add(exit_amount, fee_amount);
        builder.connect(sum, funding_tx_amount);

        AmountsTargets {
            funding_tx_amount,
            exit_amount,
            fee_amount,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        _inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_target(
            targets.funding_tx_amount,
            F::from_canonical_u64(self.funding_tx_amount),
        )?;
        pw.set_target(targets.exit_amount, F::from_canonical_u64(self.exit_amount))?;
        pw.set_target(targets.fee_amount, F::from_canonical_u64(self.fee_amount))
    }
}

pub struct Nullifier {
    hash: Digest,
}

impl Nullifier {
    pub fn new(entrinsic_tx: u64, secret: &str) -> Self {
        // Calculate the preimage by concatanating [`SALT`], the entrinsic_tx and the secret value.
        let entrinsic_tx = entrinsic_tx.to_be_bytes();
        let secret = string_to_padded_32_byte_array(secret);
        let preimage: Vec<F> = [SALT, &entrinsic_tx, &secret]
            .concat()
            .iter()
            .map(|v| F::from_canonical_u8(*v))
            .collect();

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let hash = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { hash }
    }
}

pub struct NullifierTargets {
    hash: HashOutTarget,
    salt: Vec<Target>,
    tx_id: Vec<Target>,
    secret: Vec<Target>,
}

pub struct NullifierInputs {
    salt: &'static [u8],
    tx_id: u64,
    secret: [u8; 32],
}

impl CircuitFragment for Nullifier {
    type PrivateInputs = NullifierInputs;
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let hash = builder.add_virtual_hash_public_input();
        let salt = builder.add_virtual_targets(8);
        let tx_id = builder.add_virtual_targets(8);
        let secret = builder.add_virtual_targets(32);

        let mut preimage = Vec::with_capacity(salt.len() + tx_id.len() + secret.len());
        preimage.extend(salt.clone());
        preimage.extend(tx_id.clone());
        preimage.extend(secret.clone());

        // Expose tx id as a public input.
        builder.register_public_inputs(&tx_id);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
        let computed_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        for i in 0..4 {
            builder.connect(hash.elements[i], computed_hash.elements[i]);
        }

        NullifierTargets {
            hash,
            salt,
            tx_id,
            secret,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, HashOut::from_partial(&self.hash))?;
        for (i, byte) in inputs.salt.iter().enumerate() {
            pw.set_target(targets.salt[i], F::from_canonical_u8(*byte))?;
        }
        for (i, byte) in inputs.tx_id.to_be_bytes().iter().enumerate() {
            pw.set_target(targets.tx_id[i], F::from_canonical_u8(*byte))?;
        }
        for (i, byte) in inputs.secret.iter().enumerate() {
            pw.set_target(targets.secret[i], F::from_canonical_u8(*byte))?;
        }

        Ok(())
    }
}

pub struct WormholeProofPublicInputs {
    // Prevents double-claims (double hash of salt + txid + secret)
    nullifier: Nullifier,
    // Account the user wishes to withdraw to
    // exit_account: AccountId,
    amounts: Amounts,
    // Used to verify the transaction success event
    // storage_root: [u8; 32],
    // The order that the tx was mined in, also referred to as `tx_id`
    extrinsic_index: u64,
}

impl WormholeProofPublicInputs {
    pub fn new(nullifier: Nullifier, amounts: Amounts, extrinsic_index: u64) -> Self {
        Self {
            nullifier,
            amounts,
            extrinsic_index,
        }
    }
}

pub struct WormholeProofPrivateInputs {
    // Event that resulted from funding the unspendable address
    // funding_event: Vec<u8>,
    /// Unspendable account
    unspendable_account: UnspendableAccount,
    // Proves balance
    // storage_proof: Vec<u8>,
    /// Secret value preimage of unspendable_address, this is also used in the nullifier computation
    unspendable_secret: &'static str,
}

impl WormholeProofPrivateInputs {
    pub fn new(unspendable_account: UnspendableAccount, unspendable_secret: &'static str) -> Self {
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
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    // Plonky2 circuit config setup:
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Setup all the circuits.
    let unspendable_account_targets = private_inputs.unspendable_account.circuit(&mut builder);
    let amounts_targets = public_inputs.amounts.circuit(&mut builder);
    let nullifier_targets = public_inputs.nullifier.circuit(&mut builder);

    // Convert the secret to its byte representation and pad as necessary.
    let unspendable_secret = string_to_padded_32_byte_array(private_inputs.unspendable_secret);

    let mut pw = PartialWitness::new();
    private_inputs.unspendable_account.fill_targets(
        &mut pw,
        unspendable_account_targets,
        UnspendableAccountInputs {
            salt: SALT,
            secret: unspendable_secret,
        },
    )?;
    public_inputs
        .amounts
        .fill_targets(&mut pw, amounts_targets, ())?;
    public_inputs.nullifier.fill_targets(
        &mut pw,
        nullifier_targets,
        NullifierInputs {
            salt: SALT,
            tx_id: public_inputs.extrinsic_index,
            secret: unspendable_secret,
        },
    )?;

    // Build the circuit.
    let data = builder.build::<C>();

    // Generate the proof.
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    Ok(proof)
}

/// Converts a string its representation in a 32 byte array.
fn string_to_padded_32_byte_array(string: &str) -> [u8; 32] {
    let string_bytes = string.as_bytes();
    let mut array = [0u8; 32];
    array[..string_bytes.len()].copy_from_slice(string_bytes);
    array
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::PrimeField64;

    use super::*;

    const EXPECTED_PUBLIC_INPUTS: [u64; 15] = [
        100,
        90,
        10,
        3057985780030117758,
        8797366881033976523,
        4328197692386296141,
        16319348266743790422,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    struct WormholeProofTestInputs {
        public_inputs: WormholeProofPublicInputs,
        private_inputs: WormholeProofPrivateInputs,
    }

    impl Default for WormholeProofTestInputs {
        fn default() -> Self {
            let funding_tx_amount = 100;
            let exit_amount = 90;
            let fee_amount = 10;
            let extrinsic_index = 0;

            let unspendable_secret = "secret";

            Self {
                public_inputs: WormholeProofPublicInputs::new(
                    Nullifier::new(extrinsic_index, unspendable_secret),
                    Amounts::new(funding_tx_amount, exit_amount, fee_amount),
                    extrinsic_index,
                ),
                private_inputs: WormholeProofPrivateInputs::new(
                    UnspendableAccount::new(unspendable_secret),
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
    fn only_public_inputs_are_exposed() {
        let inputs = WormholeProofTestInputs::default();
        let proof = verify(inputs.public_inputs, inputs.private_inputs).unwrap();

        for (i, input) in proof.public_inputs.iter().enumerate() {
            assert_eq!(input.to_noncanonical_u64(), EXPECTED_PUBLIC_INPUTS[i]);
        }
    }

    #[test]
    #[should_panic]
    fn build_and_verify_proof_wrong_unspendable_secret() {
        let mut inputs = WormholeProofTestInputs::default();
        inputs.private_inputs.unspendable_secret = "terces";
        verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    }

    #[test]
    #[should_panic]
    fn build_and_verify_proof_non_zero_sum_amounts() {
        let mut inputs = WormholeProofTestInputs::default();
        inputs.public_inputs.amounts.exit_amount = 200;

        verify(inputs.public_inputs, inputs.private_inputs).unwrap();
    }
}
