use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
    plonk::config::Hasher,
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
    pub hashes: Vec<Option<HashOutTarget>>,
}

#[derive(Debug, Default)]
pub struct StorageProof {
    proof: Vec<Vec<F>>,
    hashes: Vec<Option<Vec<F>>>,
}

impl StorageProof {
    /// The input is a storage proof as a tuple where each part is split at the index where the child node's
    /// hash, if any, appears within this proof node
    pub fn new(proof: Vec<(&str, Option<&str>)>) -> anyhow::Result<Self> {
        // First construct the proof and the hash array
        let mut constructed_proof = Vec::with_capacity(proof.len());
        let mut hashes = Vec::with_capacity(proof.len());
        for (left, right) in proof.into_iter() {
            // Decode hex data.
            let mut proof_node_bytes = hex::decode(left)?;
            let right = right.map(|h| hex::decode(h).unwrap());

            // If hash is not empty this is not a leaf node and we need to store the bytes
            // for a comparision later.
            if let Some(right) = right.clone() {
                proof_node_bytes.extend(right);
            }

            // We make sure to convert to field elements after an eventual hash has been appended.
            let proof_node = slice_to_field_elements(&proof_node_bytes);
            let hash = right.map(|h| slice_to_field_elements(&h)[..4].to_vec());

            println!("PROOF_NODE: {:?}", proof_node);
            println!(
                "HASHED_NODE: {:?}",
                PoseidonHash::hash_no_pad(&proof_node).elements
            );
            println!("HASH: {:?}", hash);

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
        for hash in &self.hashes {
            let hash = hash.as_ref().map(|_hash| builder.add_virtual_hash());
            hashes.push(hash);
        }

        // Setup constraints.
        let mut prev_hash: Option<HashOutTarget> = None;
        for (node, hash) in proof_data.iter().zip(hashes.iter()) {
            let node_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.to_vec());

            if let Some(prev_hash) = prev_hash {
                builder.connect_hashes(node_hash, prev_hash);
            }

            prev_hash = *hash;
            println!("{:?}", prev_hash);
        }

        println!("{:?}", prev_hash);
        let proof_root = prev_hash.expect("no root node was found in proof data");
        builder.connect_hashes(proof_root, root_hash);

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
        println!("ROOT HASH: {:?}: ", slice_to_hashout(&inputs.root_hash));
        pw.set_hash_target(targets.root_hash, slice_to_hashout(&inputs.root_hash))?;
        for (i, proof_node) in self.proof.iter().enumerate() {
            pw.set_target_arr(&targets.proof_data[i], proof_node)?;
        }
        for (i, hash) in self.hashes.iter().enumerate() {
            if let (Some(hash_t), Some(hash)) = (targets.hashes[i], hash) {
                let hash = HashOut::from_vec(hash[0..4].to_vec());
                pw.set_hash_target(hash_t, hash)?;
            }
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

    use crate::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };

    use super::*;

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

    // const ROOT_HASH: &str = "2c490f3108efc8b9cd547db5fefec5cf49f7f55033bd917e622d3149f5b2e7c4";
    const ROOT_HASH: &str = "0926568f0e5ea8bc9626a97c8c8bab6d4b110b05e5c35bb895c0679d8cecc8ad";
    const STORAGE_PROOF: [(&str, Option<&str>); 3] = [
        ("802db080583b8a9387ed08ee9b738699abfcbad1b8e29cb7b41cac563d994003c961173080ea73ee6d8e4a9eaa0bdc2c9ac5f92f3496db397ccf45a36a8204cf43228897738033781a97a90f1f06effaad425064faf81a7f63829068f52e66bc6608bc574724806ff21247e3284873ef5c60a8a4f200a14ac57ff4915b76be741327efb0de52cf80", Some("fdff83c54a927f7017bac61f875ed0be017ccea19030cb1a94707d98544d7bf9803593ea2a1d297a5b3f4f03b97b1a8d4fed67826778c6392905a2891c26cd9979807b0915aa481d80b2a4ed3b8095850bc5c71f27376285aadad77d32d953eaed83")),
        ("9f02261276cc9d1f8598ea4b6a74b15c2f3000505f0e7b9012096b41c4eb3aaf947f6ea42908010080", Some("7d2a0433270079343ebcb735a692272c38706bda9009e2d2362a0150d8b53136")),
        ("80840080", Some("0926568f0e5ea8bc9626a97c8c8bab6d4b110b05e5c35bb895c0679d8cecc8ad80fb21730f3ee7d68537e10e9ebcdb88ee2c9c34873a7d92d40d94869430122feb")),
    ];

    #[test]
    fn build_and_verify_proof() {
        let storage_proof = StorageProof::new(STORAGE_PROOF.to_vec()).unwrap();
        let inputs = StorageProofInputs {
            root_hash: hex::decode(ROOT_HASH).unwrap().try_into().unwrap(),
        };

        println!("{:?}", storage_proof);

        run_test(storage_proof, inputs).unwrap();
    }
}
