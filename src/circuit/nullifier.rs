use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use super::{CircuitFragment, D, Digest, F, slice_to_field_elements};

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 5;

#[derive(Debug, Default)]
pub struct Nullifier {
    hash: Digest,
}

impl Nullifier {
    pub fn new(preimage: &str) -> anyhow::Result<Self> {
        // Calculate the preimage by concatanating [`SALT`], the intrinsic_tx and the secret value.
        let decoded = hex::decode(preimage)?;
        let preimage = slice_to_field_elements(&decoded);

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let hash = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Ok(Self { hash })
    }
}

#[derive(Debug, Clone)]
pub struct NullifierTargets {
    hash: HashOutTarget,
    preimage: Vec<Target>,
}

#[derive(Debug, Default)]
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
    fn circuit(builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let hash = builder.add_virtual_hash_public_input();
        let preimage = builder.add_virtual_targets(PREIMAGE_NUM_TARGETS);

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
    use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};

    use crate::circuit::{
        C,
        tests::{build_and_prove_test, setup_test_builder_and_witness},
    };

    use super::*;

    fn run_test(
        nullifier: Nullifier,
        inputs: NullifierInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = Nullifier::circuit(&mut builder);

        nullifier.fill_targets(&mut pw, targets, inputs).unwrap();
        build_and_prove_test(builder, pw)
    }

    const PREIMAGE: &str =
        "776f726d686f6c650908804f8983b91253f3b2e4d49b71afc8e2c707608d9ae456990fb21591037f";

    #[test]
    fn build_and_verify_proof() {
        let nullifier = Nullifier::new(PREIMAGE).unwrap();
        let inputs = NullifierInputs::new(PREIMAGE).unwrap();
        run_test(nullifier, inputs).unwrap();
    }

    #[test]
    fn invalid_preimage_fails_proof() {
        let valid_nullifier = Nullifier::new(PREIMAGE).unwrap();

        // Flip the first byte in the first node hash.
        let mut invalid_bytes = hex::decode(PREIMAGE).unwrap();
        invalid_bytes[0] ^= 0xFF;
        let invalid_hex = hex::encode(invalid_bytes);

        let bad_inputs = NullifierInputs::new(&invalid_hex).unwrap();

        let res = run_test(valid_nullifier, bad_inputs);
        assert!(res.is_err(),);
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let hex_preimage = hex::encode(preimage_bytes);

        let nullifier = Nullifier::new(&hex_preimage).unwrap();
        assert!(!nullifier.hash.to_vec().iter().all(|x| x.is_zero()));
    }
}
