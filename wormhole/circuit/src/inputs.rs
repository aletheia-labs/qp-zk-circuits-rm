#![allow(clippy::new_without_default)]
use crate::storage_proof::ProcessedStorageProof;
use alloc::vec::Vec;
use anyhow::{anyhow, bail, Context};
use core::ops::Deref;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{felts_to_bytes, felts_to_u128, fixed_felts_to_bytes, Digest};

/// The total size of the public inputs field element vector.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 14;
pub const NULLIFIER_START_INDEX: usize = 0;
pub const NULLIFIER_END_INDEX: usize = 4;
pub const ROOT_HASH_START_INDEX: usize = 4;
pub const ROOT_HASH_END_INDEX: usize = 8;
pub const FUNDING_AMOUNT_START_INDEX: usize = 8;
pub const FUNDING_AMOUNT_END_INDEX: usize = 10;
pub const EXIT_ACCOUNT_START_INDEX: usize = 10;
pub const EXIT_ACCOUNT_END_INDEX: usize = 14;

/// A bytes digest containing various helpful methods for converting between
/// field element digests and byte digests.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytesDigest(pub [u8; 32]);

impl From<[u8; 32]> for BytesDigest {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for BytesDigest {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = value.try_into().map_err(|_| {
            anyhow!(
                "failed to deserialize bytes digest from byte vector. Expected length 32, got {}",
                value.len()
            )
        })?;
        Ok(Self(bytes))
    }
}

impl From<Digest> for BytesDigest {
    fn from(value: Digest) -> Self {
        let bytes = fixed_felts_to_bytes(value);
        Self(bytes)
    }
}

impl TryFrom<&[F]> for BytesDigest {
    type Error = anyhow::Error;

    fn try_from(value: &[F]) -> Result<Self, Self::Error> {
        let bytes = felts_to_bytes(value).try_into().map_err(|_| {
            anyhow!(
                "failed to deserialize bytes digest from field elements. Expected length 4, got {}",
                value.len()
            )
        })?;
        Ok(Self(bytes))
    }
}

impl Deref for BytesDigest {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// Amount to be withdrawn.
    pub funding_amount: u128,
    /// The nullifier.
    pub nullifier: BytesDigest,
    /// The root hash of the storage trie.
    pub root_hash: BytesDigest,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
}

/// All of the private inputs required for the circuit.
#[derive(Debug, Clone)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: [u8; 32],
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: ProcessedStorageProof,
    pub transfer_count: u64,
    pub funding_account: BytesDigest,
    /// The unspendable account hash.
    pub unspendable_account: BytesDigest,
}

impl PublicCircuitInputs {
    /// Parse a vector of `PublicCircuitInputs` from a *root aggregated* proof.
    /// `leaf_pi_len` should match the leaf circuit's public input length.
    /// `num_leaves` should match `TreeAggregationConfig.num_leaf_proofs`.
    pub fn try_from_aggregated(
        aggr: &ProofWithPublicInputs<F, C, D>,
        leaf_pi_len: usize,
        num_leaves: usize,
    ) -> anyhow::Result<Vec<Self>> {
        let leaf_public_inputs = &aggr.public_inputs;
        let expected = leaf_pi_len.checked_mul(num_leaves).ok_or_else(|| {
            anyhow::anyhow!(
                "overflow computing expected public inputs (leaf_pi_len={}, num_leaves={})",
                leaf_pi_len,
                num_leaves
            )
        })?;

        if leaf_public_inputs.len() != expected {
            anyhow::bail!(
                "aggregated public inputs should contain: {} (= {} leaves × {} fields), got: {}",
                expected,
                num_leaves,
                leaf_pi_len,
                leaf_public_inputs.len()
            );
        }

        leaf_public_inputs
            .chunks(leaf_pi_len)
            .map(Self::try_from_slice)
            .collect()
    }

    pub fn try_from_slice(pis: &[GoldilocksField]) -> anyhow::Result<Self> {
        const LEAF_PI_LEN: usize = 14;
        // Public inputs are ordered as follows:
        // Nullifier.hash: 4 felts
        // StorageProof.root_hash: 4 felts
        // StorageProof.funding_amount: 2 felts
        // ExitAccount.address: 4 felts
        if pis.len() != LEAF_PI_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                LEAF_PI_LEN,
                pis.len()
            )
        }
        let nullifier = BytesDigest::try_from(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to deserialize nullifier hash")?;
        let root_hash = BytesDigest::try_from(&pis[ROOT_HASH_START_INDEX..ROOT_HASH_END_INDEX])
            .context("failed to deserialize root hash")?;
        let funding_amount = felts_to_u128(
            <[F; 2]>::try_from(&pis[FUNDING_AMOUNT_START_INDEX..FUNDING_AMOUNT_END_INDEX])
                .context("failed to deserialize funding amount")?,
        );
        let exit_account =
            BytesDigest::try_from(&pis[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX])
                .context("failed to deserialize exit account")?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
        })
    }
}

impl TryFrom<&ProofWithPublicInputs<F, C, D>> for PublicCircuitInputs {
    type Error = anyhow::Error;

    fn try_from(proof: &ProofWithPublicInputs<F, C, D>) -> Result<Self, Self::Error> {
        Self::try_from_slice(&proof.public_inputs)
            .context("failed to deserialize public inputs from proof")
    }
}
