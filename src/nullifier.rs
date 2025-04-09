use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{
    string_to_padded_32_byte_array, CircuitFragment, Digest, D, F, SALT, SECRET_NUM_BYTES,
};

pub struct Nullifier {
    hash: Digest,
}

impl Nullifier {
    pub fn new(intrinsic_tx: u64, secret: &str) -> Self {
        // Calculate the preimage by concatanating [`SALT`], the intrinsic_tx and the secret value.
        let intrinsic_tx = intrinsic_tx.to_be_bytes();
        let secret = string_to_padded_32_byte_array(secret);
        let preimage: Vec<F> = [SALT, &intrinsic_tx, &secret]
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
    secret: [u8; SECRET_NUM_BYTES],
}

impl NullifierInputs {
    pub fn new(tx_id: u64, secret: [u8; SECRET_NUM_BYTES]) -> Self {
        Self {
            salt: SALT,
            tx_id,
            secret,
        }
    }
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
        let secret = builder.add_virtual_targets(SECRET_NUM_BYTES);

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
        builder.connect_hashes(computed_hash, hash);

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
        pw.set_hash_target(targets.hash, self.hash.into())?;
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
