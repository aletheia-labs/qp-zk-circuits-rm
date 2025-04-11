use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{slice_to_field_elements, CircuitFragment, Digest, D, F};

pub struct Nullifier {
    hash: Digest,
    preimage_num_targets: usize,
}

impl Nullifier {
    pub fn new(preimage: &str) -> anyhow::Result<Self> {
        // Calculate the preimage by concatanating [`SALT`], the intrinsic_tx and the secret value.
        let decoded = hex::decode(preimage)?;
        let preimage = slice_to_field_elements(&decoded);

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let hash = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Ok(Self {
            hash,
            preimage_num_targets: preimage.len(),
        })
    }
}

pub struct NullifierTargets {
    hash: HashOutTarget,
    preimage: Vec<Target>,
}

pub struct NullifierInputs {
    preimage: Vec<F>,
}

impl NullifierInputs {
    pub fn new(preimage: &str) -> anyhow::Result<Self> {
        let decoded = hex::decode(preimage)?;
        let preimage = slice_to_field_elements(&decoded);
        Ok(Self { preimage })
    }
}

impl CircuitFragment for Nullifier {
    type PrivateInputs = NullifierInputs;
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let hash = builder.add_virtual_hash_public_input();
        let preimage = builder.add_virtual_targets(self.preimage_num_targets);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let computed_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(computed_hash, hash);

        NullifierTargets { hash, preimage }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        pw.set_target_arr(&targets.preimage, &inputs.preimage)?;

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

        let nullifier = Nullifier::new(PREIMAGE).unwrap();
        let targets = nullifier.circuit(&mut builder);

        let inputs = NullifierInputs::new(PREIMAGE).unwrap();
        nullifier.fill_targets(&mut pw, targets, inputs).unwrap();

        let data = builder.build::<C>();

        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
