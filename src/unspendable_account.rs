use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{slice_to_field_elements, CircuitFragment, Digest, D, F};

pub type AccountId = Digest;

pub struct UnspendableAccount {
    account_id: AccountId,
    preimage_num_targets: usize,
}

impl UnspendableAccount {
    pub fn new(preimage: &str) -> anyhow::Result<Self> {
        // First, convert the preimage to its representation as field elements.
        let decoded = hex::decode(preimage)?;
        let preimage = slice_to_field_elements(&decoded);

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let account_id = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Ok(Self {
            account_id,
            preimage_num_targets: preimage.len(),
        })
    }
}

pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    preimage: Vec<Target>,
}

pub struct UnspendableAccountInputs {
    preimage: Vec<F>,
}

impl UnspendableAccountInputs {
    pub fn new(preimage: &str) -> anyhow::Result<Self> {
        let decoded = hex::decode(preimage)?;
        let preimage = slice_to_field_elements(&decoded);
        Ok(Self { preimage })
    }
}

impl CircuitFragment for UnspendableAccount {
    type PrivateInputs = UnspendableAccountInputs;
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let account_id = builder.add_virtual_hash_public_input();
        let preimage = builder.add_virtual_targets(self.preimage_num_targets);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(generated_account, account_id);

        UnspendableAccountTargets {
            account_id,
            preimage,
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
        for (i, element) in inputs.preimage.into_iter().enumerate() {
            pw.set_target(targets.preimage[i], element)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use plonky2::plonk::circuit_data::CircuitConfig;

    use crate::C;

    use super::*;

    const PREIMAGE: &str = "e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81";

    #[test]
    fn build_and_verify_proof() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();

        let unspendable_account = UnspendableAccount::new(PREIMAGE).unwrap();
        let targets = unspendable_account.circuit(&mut builder);

        let inputs = UnspendableAccountInputs::new(PREIMAGE).unwrap();
        unspendable_account
            .fill_targets(&mut pw, targets, inputs)
            .unwrap();

        let data = builder.build::<C>();

        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
