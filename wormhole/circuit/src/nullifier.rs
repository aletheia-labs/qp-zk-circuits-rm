#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::array;
use core::mem::size_of;
use zk_circuits_common::utils::digest_felts_to_bytes;

#[cfg(feature = "std")]
use std::vec::Vec;
use zk_circuits_common::utils::digest_bytes_to_felts;

use crate::codec::ByteCodec;
use crate::codec::FieldElementCodec;
use crate::inputs::CircuitInputs;
use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::utils::{
    injective_bytes_to_felts, injective_felts_to_bytes, injective_string_to_felt, u64_to_felts,
    BytesDigest, Digest,
};

pub const NULLIFIER_SALT: &str = "~nullif~";
pub const SECRET_NUM_TARGETS: usize = 8;
pub const NONCE_NUM_TARGETS: usize = 1;
pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = 4;
pub const TRANSFER_COUNT_NUM_TARGETS: usize = 2;
pub const PREIMAGE_NUM_TARGETS: usize =
    SECRET_NUM_TARGETS + NONCE_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_FELTS: usize = 4 + 4 + 1 + 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    pub hash: Digest,
    pub secret: Vec<F>,
    transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS],
}

impl Nullifier {
    pub fn new(digest: BytesDigest, secret: &[u8], transfer_count: u64) -> Self {
        let hash = digest_bytes_to_felts(digest);
        let secret = injective_bytes_to_felts(secret);
        let transfer_count = u64_to_felts(transfer_count);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }

    pub fn from_preimage(secret: &[u8], transfer_count: u64) -> Self {
        let mut preimage = Vec::new();

        let salt = injective_string_to_felt(NULLIFIER_SALT);
        let secret = injective_bytes_to_felts(secret);
        let transfer_count = u64_to_felts(transfer_count);

        preimage.extend(salt);
        preimage.extend(secret.clone());
        preimage.extend(transfer_count);

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        let hash = Digest::from(outer_hash);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_felts_to_bytes(self.hash));
        bytes.extend(injective_felts_to_bytes(&self.secret));
        bytes.extend(injective_felts_to_bytes(&self.transfer_count));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let f_size = size_of::<F>(); // 8 bytes
        let hash_size = 4 * f_size; // 4 field elements
        let secret_size = 8 * f_size; // 8 field elements
        let transfer_count_size = 2 * f_size; // 2 field element
        let total_size = hash_size + secret_size + transfer_count_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for Nullifier, got: {}",
                total_size,
                slice.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let digest = slice[offset..offset + hash_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        let hash = digest_bytes_to_felts(digest);
        offset += hash_size;

        // Deserialize secret
        let secret = injective_bytes_to_felts(&slice[offset..offset + secret_size]);
        if secret.len() != 8 {
            return Err(anyhow::anyhow!(
                "Expected 8 field elements for secret, got: {}",
                secret.len()
            ));
        }
        offset += secret_size;

        // Deserialize transfer_count
        let transfer_count = injective_bytes_to_felts(&slice[offset..offset + transfer_count_size]);
        if transfer_count.len() != 2 {
            return Err(anyhow::anyhow!(
                "Expected 2 field elements for transfer_count, got: {}",
                transfer_count.len()
            ));
        }
        let transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS] = transfer_count.try_into().unwrap();

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
}

impl FieldElementCodec for Nullifier {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.hash.to_vec());
        elements.extend(self.secret.clone());
        elements.extend(self.transfer_count);
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        let hash_size = 4; // 32 bytes w/ 64 bit limbs = 4 field elements
        let secret_size = 8; // 32 bytes w/ 32 bit limbs = 8 field elements
        let transfer_count_size = 2; // 8 bytes w/ 32 bit limbs field element
        let total_size = hash_size + secret_size + transfer_count_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for Nullifier, got: {}",
                total_size,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let hash = elements[offset..offset + hash_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        offset += hash_size;

        // Deserialize secret
        let secret = elements[offset..offset + secret_size].to_vec();
        offset += secret_size;

        // Deserialize funding_nonce
        let transfer_count = elements[offset..offset + transfer_count_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier transfer_count"))?;

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
}

impl From<&CircuitInputs> for Nullifier {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(
            inputs.public.nullifier,
            &inputs.private.secret,
            inputs.private.transfer_count,
        )
    }
}

#[derive(Debug, Clone)]
pub struct NullifierTargets {
    pub hash: HashOutTarget,
    pub secret: Vec<Target>,
    pub transfer_count: [Target; TRANSFER_COUNT_NUM_TARGETS],
}

impl NullifierTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            hash: builder.add_virtual_hash_public_input(),
            secret: builder.add_virtual_targets(SECRET_NUM_TARGETS),
            transfer_count: array::from_fn(|_| builder.add_virtual_target()),
        }
    }
}

#[cfg(feature = "std")]
impl CircuitFragment for Nullifier {
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(
        &Self::Targets {
            hash,
            ref secret,
            ref transfer_count,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let mut preimage = Vec::new();
        let salt_felts = injective_string_to_felt(NULLIFIER_SALT);
        preimage.push(builder.constant(salt_felts[0]));
        preimage.push(builder.constant(salt_felts[1]));
        preimage.extend(secret);
        preimage.extend(transfer_count);

        // Range check all the preimage targets to be 32 bits.
        for target in preimage.iter() {
            builder.range_check(*target, 32);
        }

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let computed_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(computed_hash, hash);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        pw.set_target_arr(&targets.secret, &self.secret)?;
        pw.set_target_arr(&targets.transfer_count, &self.transfer_count)?;
        Ok(())
    }
}
