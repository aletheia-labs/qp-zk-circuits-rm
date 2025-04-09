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

pub type AccountId = Digest;

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
    secret: [u8; SECRET_NUM_BYTES],
}

impl UnspendableAccountInputs {
    pub fn new(secret: [u8; SECRET_NUM_BYTES]) -> Self {
        Self { salt: SALT, secret }
    }
}

impl CircuitFragment for UnspendableAccount {
    type PrivateInputs = UnspendableAccountInputs;
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let account_id = builder.add_virtual_hash_public_input();
        let salt = builder.add_virtual_targets(8);
        let secret = builder.add_virtual_targets(SECRET_NUM_BYTES);

        let mut preimage = Vec::with_capacity(salt.len() + secret.len());
        preimage.extend(salt.clone());
        preimage.extend(secret.clone());

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(generated_account, account_id);

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
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        for (i, byte) in inputs.salt.iter().enumerate() {
            pw.set_target(targets.salt[i], F::from_canonical_u8(*byte))?;
        }
        for (i, byte) in inputs.secret.iter().enumerate() {
            pw.set_target(targets.secret[i], F::from_canonical_u8(*byte))?;
        }

        Ok(())
    }
}
