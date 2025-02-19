use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::keccak::KeccakHash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};

// TODO: Correct constants.
pub const ACCOUNT_HASH_SIZE: usize = 16;
pub const SALT: &str = "~wormhole~";

pub struct AccountId(KeccakHash<ACCOUNT_HASH_SIZE>);

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
    /// Event that resulted from funding the unspendable address
    funding_event: Vec<u8>,
    /// Unspendable account
    unspendable_account: AccountId,
    /// Proves balance
    storage_proof: Vec<u8>,
    /// Secret value preimage of unspendable_address, this is also used in the nullifier computation
    unspendable_secret: Vec<u8>,
}

// Plonky2 setup parameters.
const D: usize = 2; // D=2 provides 100-bits of security
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

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
pub fn verify(public_inputs: WormholeProofPublicInputs) {
    // Plonky2 circuit setup:
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Register all public inputs.
    let (funding_tx_amount, exit_amount, fee_amount) = funding_amount_circuit(&mut builder);

    let mut pw = PartialWitness::new();
    pw.set_target(
        funding_tx_amount,
        F::from_canonical_u64(public_inputs.funding_tx_amount),
    )
    .unwrap();
    pw.set_target(
        exit_amount,
        F::from_canonical_u64(public_inputs.exit_amount),
    )
    .unwrap();
    pw.set_target(fee_amount, F::from_canonical_u64(public_inputs.fee_amount))
        .unwrap();

    // Build the circuit.
    let data = builder.build::<C>();

    // Generate the proof.
    let proof = data.prove(pw).unwrap();

    println!(
        "funding amount: {}\nexit amount: {}\nfee_amount: {}\n",
        proof.public_inputs[0], proof.public_inputs[1], proof.public_inputs[2]
    );

    data.verify(proof).unwrap();
}

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

    #[test]
    fn build_and_verify_proof() {
        // Setup variables to prove.
        let funding_tx_amount = 100;
        let exit_amount = 90;
        let fee_amount = 10;

        let public_inputs =
            WormholeProofPublicInputs::new(funding_tx_amount, exit_amount, fee_amount);
        verify(public_inputs);
    }
}
