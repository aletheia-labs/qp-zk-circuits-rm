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
pub type Digest = [F; 4];
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;

// TODO: Correct constants.
pub const ACCOUNT_HASH_SIZE: usize = 16;
pub const SALT: &[u8] = "~wormhole~".as_bytes();

pub type AccountId = Digest;

pub trait CircuitFragment {
    type Targets;

    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets;

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()>;
}

pub struct UnspendableAccount {
    account_id: AccountId,
    preimage: Vec<F>,
}

impl UnspendableAccount {
    pub fn new(account_id: AccountId, secret: &str) -> Self {
        // Calculate the preimage by concatanating [`SALT`] and the secret value.
        let secret = secret.as_bytes().to_vec();
        let preimage: Vec<F> = [SALT, &secret]
            .concat()
            .iter()
            .map(|v| F::from_canonical_u8(*v))
            .collect();

        // FIXME: For debugging.
        println!("SALT: {}", String::from_utf8(SALT.to_vec()).unwrap());
        println!("SECRET: {}", String::from_utf8(secret).unwrap());
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        println!("HASH: {:?}", inner_hash);
        let double_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        println!("DOUBLE HASH: {:?}", double_hash);

        Self {
            account_id,
            preimage,
        }
    }
}

pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    preimage: Vec<Target>,
}

impl CircuitFragment for UnspendableAccount {
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let account_id = builder.add_virtual_hash();
        let preimage = builder.add_virtual_targets(self.preimage.len());

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        // NOTE: We assume that addresses are generated with Poseidon. Should double-check sometime.
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        for i in 0..4 {
            builder.connect(account_id.elements[i], generated_account.elements[i]);
        }

        UnspendableAccountTargets {
            account_id,
            preimage,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, HashOut::from_partial(&self.account_id))?;
        for (i, v) in self.preimage.iter().enumerate() {
            pw.set_target(targets.preimage[i], *v)?;
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
    ) -> anyhow::Result<()> {
        pw.set_target(
            targets.funding_tx_amount,
            F::from_canonical_u64(self.funding_tx_amount),
        )?;
        pw.set_target(targets.exit_amount, F::from_canonical_u64(self.exit_amount))?;
        pw.set_target(targets.fee_amount, F::from_canonical_u64(self.fee_amount))
    }
}

pub struct WormholeProofPublicInputs {
    // Prevents double-claims (double hash of salt + txid + secret)
    // nullifier: [u8; 64],
    // Account the user wishes to withdraw to
    // exit_account: AccountId,
    amounts: Amounts,
    // Used to verify the transaction success event
    // storage_root: [u8; 32],
    // The order that the tx was mined in
    // extrinsic_index: u64,
}

impl WormholeProofPublicInputs {
    pub fn new(amounts: Amounts) -> Self {
        Self { amounts }
    }
}

pub struct WormholeProofPrivateInputs {
    // Event that resulted from funding the unspendable address
    // funding_event: Vec<u8>,
    /// Unspendable account
    unspendable_account: UnspendableAccount,
    // Proves balance
    // storage_proof: Vec<u8>,
}

impl WormholeProofPrivateInputs {
    pub fn new(unspendable_account: UnspendableAccount) -> Self {
        Self {
            unspendable_account,
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

    // Setup all the circuits.
    let unspendable_account_targets = private_inputs.unspendable_account.circuit(&mut builder);
    let amounts_targets = public_inputs.amounts.circuit(&mut builder);

    let mut pw = PartialWitness::new();
    private_inputs
        .unspendable_account
        .fill_targets(&mut pw, unspendable_account_targets)?;
    public_inputs
        .amounts
        .fill_targets(&mut pw, amounts_targets)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_unspendable_account_id() -> Digest {
        [
            F::from_canonical_u64(4400158269619346328),
            F::from_canonical_u64(7835876850004545748),
            F::from_canonical_u64(9949762737399135748),
            F::from_canonical_u64(17261303441366130639),
        ]
    }

    struct WormholeProofTestInputs {
        public_inputs: WormholeProofPublicInputs,
        private_inputs: WormholeProofPrivateInputs,
    }

    impl Default for WormholeProofTestInputs {
        fn default() -> Self {
            let funding_tx_amount = 100;
            let exit_amount = 90;
            let fee_amount = 10;

            Self {
                public_inputs: WormholeProofPublicInputs::new(Amounts::new(
                    funding_tx_amount,
                    exit_amount,
                    fee_amount,
                )),
                private_inputs: WormholeProofPrivateInputs::new(UnspendableAccount::new(
                    generate_unspendable_account_id(),
                    "~secret~",
                )),
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
        inputs.private_inputs.unspendable_account =
            UnspendableAccount::new(generate_unspendable_account_id(), "~wrong-secret~");

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
