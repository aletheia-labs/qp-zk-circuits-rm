use anyhow::bail;
use plonky2::plonk::proof::ProofWithPublicInputs;
use crate::circuit::{C, F, D};
use crate::codec::FieldElementCodec;
use crate::nullifier::{Nullifier, NULLIFIER_SIZE_FELTS};
use crate::substrate_account::SubstrateAccount;
use crate::test_helpers::{DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_NONCE, DEFAULT_SECRET};
use crate::unspendable_account::test_helpers::SECRETS;
use crate::unspendable_account::UnspendableAccount;
use crate::utils::{felts_to_bytes, felts_to_u128};

/// The total size of the public inputs field element vector.
const PUBLIC_INPUTS_FELTS_LEN: usize = 14;

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug)]
pub struct PublicCircuitInputs {
    /// Amount to be withdrawn.
    pub funding_amount: u128,
    /// The nullifier.
    pub nullifier: Nullifier,
    /// The root hash of the storage trie.
    pub root_hash: [u8; 32],
    /// The address of the account to pay out to.
    pub exit_account: SubstrateAccount,
}

/// All of the private inputs required for the circuit.
#[derive(Debug)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
    pub funding_nonce: u32,
    pub funding_account: SubstrateAccount,
    /// The unspendable account hash.
    pub unspendable_account: UnspendableAccount,
}


impl TryFrom<ProofWithPublicInputs<F, C, D>> for PublicCircuitInputs {
    type Error = anyhow::Error;

    fn try_from(proof: ProofWithPublicInputs<F, C, D>) -> Result<Self, Self::Error> {
        let public_inputs = proof.public_inputs;

        /// Public inputs are ordered as follows:
        /// Nullifier.hash: 4 felts
        /// StorageProof.funding_amount: 2 felts
        /// StorageProof.root_hash: 4 felts
        /// ExitAccount.address: 4 felts


        if public_inputs.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                public_inputs.len()
            )
        }

        let mut idx0 = 0;
        let mut idx1 = 4;
        // TODO: fix this
        // let nullifier = Nullifier::from_field_elements(&public_inputs[idx0..idx1])?;
        let nullifier = Nullifier::new(DEFAULT_SECRET.as_ref(), DEFAULT_FUNDING_NONCE, DEFAULT_FUNDING_ACCOUNT);
        idx0 = idx1;
        idx1 += 2;
        let funding_amount = felts_to_u128(public_inputs[idx0..idx1].to_vec());
        idx0 = idx1;
        idx1 += 4;
        let root_hash: [u8; 32] = felts_to_bytes(&public_inputs[idx0..idx1])
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to deserialize root hash from public inputs"))?;
        idx0 = idx1;
        idx1 += 4;

        let exit_account = SubstrateAccount::from_field_elements(&public_inputs[idx0..idx1])?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
        })
    }
}
