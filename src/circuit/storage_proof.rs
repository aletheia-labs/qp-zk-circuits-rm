use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
};

use super::{CircuitFragment, D, F, gadgets::is_const_less_than, slice_to_field_elements};

pub const MAX_PROOF_LEN: usize = 64;
pub const PROOF_NODE_MAX_SIZE: usize = 73;

#[derive(Debug, Default)]
pub struct StorageProofInputs {
    pub root_hash: [u8; 32],
}

impl StorageProofInputs {
    pub fn new(root_hash: [u8; 32]) -> Self {
        Self { root_hash }
    }
}

#[derive(Debug, Clone)]
pub struct StorageProofTargets {
    pub root_hash: HashOutTarget,
    pub proof_len: Target,
    pub proof_data: Vec<Vec<Target>>,
    pub hashes: Vec<HashOutTarget>,
}

#[derive(Debug)]
pub struct StorageProof {
    proof: Vec<Vec<F>>,
    hashes: Vec<Vec<F>>,
}

impl StorageProof {
    /// The input is a storage proof as a tuple where each part is split at the index where the child node's
    /// hash, if any, appears within this proof node
    pub fn new(proof: Vec<(&str, &str)>) -> anyhow::Result<Self> {
        // First construct the proof and the hash array
        let mut constructed_proof = Vec::with_capacity(proof.len());
        let mut hashes = Vec::with_capacity(proof.len());
        for (left, right) in proof.into_iter() {
            // Decode hex data.
            let mut proof_node_bytes = hex::decode(left)?;
            let right = hex::decode(right)?;

            proof_node_bytes.extend(right.clone());

            // We make sure to convert to field elements after an eventual hash has been appended.
            let proof_node = slice_to_field_elements(&proof_node_bytes);
            let hash = slice_to_field_elements(&right)[..4].to_vec();

            constructed_proof.push(proof_node);
            hashes.push(hash);
        }

        Ok(StorageProof {
            proof: constructed_proof,
            hashes,
        })
    }
}

impl CircuitFragment for StorageProof {
    type PrivateInputs = StorageProofInputs;
    type Targets = StorageProofTargets;

    fn circuit(
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> Self::Targets {
        // Setup targets. Each 8-bytes are represented as their equivalent field element. We also
        // need to track total proof length to allow for variable length.
        let proof_len = builder.add_virtual_target();

        let root_hash = builder.add_virtual_hash_public_input();
        let mut proof_data = Vec::with_capacity(MAX_PROOF_LEN);
        for _ in 0..MAX_PROOF_LEN {
            let proof_node = builder.add_virtual_targets(PROOF_NODE_MAX_SIZE);
            proof_data.push(proof_node);
        }

        let mut hashes = Vec::with_capacity(MAX_PROOF_LEN);
        for _ in 0..MAX_PROOF_LEN {
            let hash = builder.add_virtual_hash();
            hashes.push(hash);
        }

        // Setup constraints.
        // The first node should be the root node so we initialize `prev_hash` to the provided `root_hash`.
        let mut prev_hash = root_hash;
        let n_log = (usize::BITS - (MAX_PROOF_LEN - 1).leading_zeros()) as usize;
        for i in 0..MAX_PROOF_LEN {
            let node = &proof_data[i];

            let is_proof_node = is_const_less_than(builder, i, proof_len, n_log);
            let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.to_vec());

            for y in 0..4 {
                let diff = builder.sub(computed_hash.elements[y], prev_hash.elements[y]);
                let result = builder.mul(diff, is_proof_node.target);
                let zero = builder.zero();
                builder.connect(result, zero);
            }

            // Update `prev_hash` to the hash of the child that's stored within this node.
            prev_hash = hashes[i];
        }

        StorageProofTargets {
            root_hash,
            proof_len,
            proof_data,
            hashes,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.root_hash, slice_to_hashout(&inputs.root_hash))?;
        pw.set_target(targets.proof_len, F::from_canonical_usize(self.proof.len()))?;
        for i in 0..MAX_PROOF_LEN {
            let proof_node = match self.proof.get(i) {
                Some(node) => node,
                None => &vec![F::ZERO; PROOF_NODE_MAX_SIZE],
            };

            // NOTE: Can we avoid cloning?
            let mut padded_proof_node = proof_node.clone();
            padded_proof_node.resize(PROOF_NODE_MAX_SIZE, F::ZERO);

            pw.set_target_arr(&targets.proof_data[i], &padded_proof_node)?;
        }
        for i in 0..MAX_PROOF_LEN {
            let hash = match self.hashes.get(i) {
                Some(hash) => hash,
                None => &vec![F::ZERO; 4],
            };
            pw.set_hash_target(targets.hashes[i], HashOut::from_partial(&hash[..4]))?;
        }

        Ok(())
    }
}

fn slice_to_hashout(slice: &[u8]) -> HashOut<F> {
    let elements = slice_to_field_elements(slice);
    HashOut {
        elements: elements.try_into().unwrap(),
    }
}

#[cfg(any(test, feature = "bench"))]
pub mod test_helpers {
    use super::StorageProof;

    pub const ROOT_HASH: &str = "77eb9d80cd12acfd902b459eb3b8876f05f31ef6a17ed5fdb060ee0e86dd8139";
    pub const STORAGE_PROOF: [(&str, &str); 3] = [
        (
            "802cb08072547dce8ca905abf49c9c644951ff048087cc6f4b497fcc6c24e5592da3bc6a80c9f21db91c755ab0e99f00c73c93eb1742e9d8ba3facffa6e5fda8718006e05e80e4faa006b3beae9cb837950c42a2ab760843d05d224dc437b1add4627ddf6b4580",
            "68ff0ee21014648cb565ea90c578e0d345b51e857ecb71aaa8e307e20655a83680d8496e0fd1b138c06197ed42f322409c66a8abafd87b3256089ea7777495992180966518d63d0d450bdf3a4f16bb755b96e022464082e2cb3cf9072dd9ef7c9b53",
        ),
        (
            "9f02261276cc9d1f8598ea4b6a74b15c2f3000505f0e7b9012096b41c4eb3aaf947f6ea42908010080",
            "91a67194de54f5741ef011a470a09ad4319935c7ddc4ec11f5a9fa75dd173bd8",
        ),
        (
            "80840080",
            "2febfc925f8398a1cf35c5de15443d3940255e574ce541f7e67a3f86dbc2a98580cbfbed5faf5b9f416c54ee9d0217312d230bcc0cb57c5817dbdd7f7df9006a63",
        ),
    ];

    impl Default for StorageProof {
        fn default() -> Self {
            StorageProof::new(STORAGE_PROOF.to_vec()).unwrap()
        }
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use std::panic;

    use super::{
        test_helpers::{ROOT_HASH, STORAGE_PROOF},
        *,
    };
    use crate::circuit::{
        C,
        tests::{build_and_prove_test, setup_test_builder_and_witness},
    };
    use rand::Rng;

    fn run_test(
        storage_proof: StorageProof,
        inputs: StorageProofInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = StorageProof::circuit(&mut builder);

        storage_proof
            .fill_targets(&mut pw, targets, inputs)
            .unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_proof() {
        let storage_proof = StorageProof::new(STORAGE_PROOF.to_vec()).unwrap();
        let inputs = StorageProofInputs {
            root_hash: hex::decode(ROOT_HASH).unwrap().try_into().unwrap(),
        };

        run_test(storage_proof, inputs).unwrap();
    }

    #[test]
    #[should_panic]
    fn invalid_root_hash_fails() {
        let proof = StorageProof::new(STORAGE_PROOF.to_vec()).unwrap();
        let inputs = StorageProofInputs {
            root_hash: [0u8; 32],
        };

        run_test(proof, inputs).unwrap();
    }

    #[test]
    #[should_panic]
    fn tampered_proof_fails() {
        let mut tampered_proof = STORAGE_PROOF.to_vec();

        // Flip the first byte in the first node hash.
        let mut right_bytes = hex::decode(tampered_proof[0].1).unwrap();
        right_bytes[0] ^= 0xFF;
        let right_bytes_hex = hex::encode(&right_bytes);
        tampered_proof[0].1 = &right_bytes_hex;

        let proof = StorageProof::new(tampered_proof).unwrap();
        let inputs = StorageProofInputs {
            root_hash: hex::decode(ROOT_HASH).unwrap().try_into().unwrap(),
        };

        run_test(proof, inputs).unwrap();
    }

    #[ignore = "performance"]
    #[test]
    fn fuzz_tampered_proof() {
        let mut rng = rand::rng();

        // Number of fuzzing iterations
        const FUZZ_ITERATIONS: usize = 1000;
        let mut panic_count = 0;

        for i in 0..FUZZ_ITERATIONS {
            // Clone the original storage proof
            let mut tampered_proof = STORAGE_PROOF.to_vec();

            // Randomly select a node in the proof to tamper
            let node_index = rng.random_range(0..tampered_proof.len());

            // Decode the hex string of the selected node
            let mut bytes = hex::decode(tampered_proof[node_index].1).unwrap();

            // Randomly select a byte to flip
            let byte_index = rng.random_range(0..bytes.len());

            // Flip random bits in the selected byte (e.g., XOR with a random value)
            bytes[byte_index] ^= rng.random_range(1..=255);

            // Encode the tampered bytes back to hex
            let tampered_hex = hex::encode(&bytes);
            tampered_proof[node_index].1 = &tampered_hex;

            // Create the proof and inputs
            let proof = StorageProof::new(tampered_proof).unwrap();
            let inputs = StorageProofInputs {
                root_hash: hex::decode(ROOT_HASH).unwrap().try_into().unwrap(),
            };

            // Catch panic from run_test
            let result = panic::catch_unwind(|| {
                run_test(proof, inputs).unwrap();
            });

            if result.is_err() {
                panic_count += 1;
            } else {
                // Optionally log cases where tampering didn't cause a panic
                println!("Iteration {}: No panic occurred for tampered proof", i);
            }
        }

        assert_eq!(
            panic_count, FUZZ_ITERATIONS,
            "Only {} out of {} iterations panicked",
            panic_count, FUZZ_ITERATIONS
        );
    }
}
