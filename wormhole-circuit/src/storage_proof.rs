use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
};

use crate::{slice_to_field_elements, CircuitFragment, D, F};

#[derive(Debug, Default)]
pub struct StorageProofInputs {
    pub root_hash: [u8; 32],
}

#[derive(Debug)]
pub struct StorageProofTargets {
    pub root_hash: HashOutTarget,
    pub proof_data: Vec<Vec<Target>>,
    pub hashes: Vec<HashOutTarget>,
}

#[derive(Debug, Default)]
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
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> Self::Targets {
        let root_hash = builder.add_virtual_hash_public_input();
        let num_nodes = self.proof.len();
        let mut proof_data = Vec::with_capacity(num_nodes);
        for node in &self.proof {
            let proof_node = builder.add_virtual_targets(node.len());
            proof_data.push(proof_node);
        }

        let mut hashes = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            let hash = builder.add_virtual_hash();
            hashes.push(hash);
        }

        // Setup constraints.
        // The first node should be the root node so we initialize `prev_hash` to the provided `root_hash`.
        let mut prev_hash = root_hash;
        for (node, hash) in proof_data.iter().zip(hashes.iter()) {
            let node_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.to_vec());
            builder.connect_hashes(node_hash, prev_hash);

            // Update `prev_hash` to the hash of the child that's stored within this node.
            prev_hash = *hash;
        }

        StorageProofTargets {
            root_hash,
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
        for (i, proof_node) in self.proof.iter().enumerate() {
            pw.set_target_arr(&targets.proof_data[i], proof_node)?;
        }
        for (i, hash) in self.hashes.iter().enumerate() {
            let hash = HashOut::from_vec(hash[0..4].to_vec());
            pw.set_hash_target(targets.hashes[i], hash)?;
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

#[cfg(test)]
mod tests {
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use std::panic;

    use super::*;
    use crate::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };
    use rand::Rng;

    fn run_test(
        storage_proof: StorageProof,
        inputs: StorageProofInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = storage_proof.circuit(&mut builder);

        storage_proof
            .fill_targets(&mut pw, targets, inputs)
            .unwrap();
        build_and_prove_test(builder, pw)
    }

    const ROOT_HASH: &str = "f8f5347502a46d864cc68990c59da63f61a05e3c15950b3da99cae444f2e8a52";
    const STORAGE_PROOF: [(&str, &str); 3] = [
        ("802db080583b8a9387ed08ee9b738699abfcbad1b8e29cb7b41cac563d994003c9611730803bc4b2764d479f2f6fd28bc8023231abaeca530e4eae41dc0abd9715efd0031d8033781a97a90f1f06effaad425064faf81a7f63829068f52e66bc6608bc574724806ff21247e3284873ef5c60a8a4f200a14ac57ff4915b76be741327efb0de52cf80", "fdff83c54a927f7017bac61f875ed0be017ccea19030cb1a94707d98544d7bf9803593ea2a1d297a5b3f4f03b97b1a8d4fed67826778c6392905a2891c26cd997980b5524cd2cc83f81c64c113875ce77237584d2d59783fdce36a143d40e53ce4a7"),
        ("9f02261276cc9d1f8598ea4b6a74b15c2f3000505f0e7b9012096b41c4eb3aaf947f6ea42908010080", "7d2a0433270079343ebcb735a692272c38706bda9009e2d2362a0150d8b53136"),
        ("80840080", "0926568f0e5ea8bc9626a97c8c8bab6d4b110b05e5c35bb895c0679d8cecc8ad80fb21730f3ee7d68537e10e9ebcdb88ee2c9c34873a7d92d40d94869430122feb"),
    ];

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
