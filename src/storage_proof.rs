use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
};

use crate::{slice_to_field_elements, CircuitFragment, D, F};

#[derive(Debug)]
struct ProofNode {
    hash: HashOutTarget,
}

impl ProofNode {
    pub fn new(hash: HashOutTarget) -> Self {
        ProofNode { hash }
    }
}

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
    proof: Vec<Vec<u8>>,
    hashes: Vec<Option<Vec<u8>>>,
}

impl StorageProof {
    /// The input is a storage proof as a tuple where each part is split at the index where the child node's
    /// hash, if any, appears within this proof node
    pub fn new(proof: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Self {
        let mut constructed_proof = Vec::with_capacity(proof.len());
        let mut hashes = Vec::with_capacity(proof.len());
        for (mut proof_node, hash) in proof.into_iter() {
            // If hash is not empty this is not a leaf node and we need to store the bytes
            // for a comparision later.
            if let Some(hash) = hash.clone() {
                proof_node.extend(hash);
            }
            constructed_proof.push(proof_node);
            hashes.push(hash);
        }
        StorageProof {
            proof: constructed_proof,
            hashes,
        }
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
        for _ in 0..num_nodes {
            let proof_node = builder.add_virtual_targets(num_nodes);
            proof_data.push(proof_node);
        }

        let mut hashes = Vec::with_capacity(num_nodes);
        for hash in &self.hashes {
            let hash = hash.as_ref().map(|_hash| builder.add_virtual_hash());
            hashes.push(hash);
        }

        // Setup constraints.
        let mut prev_node: Option<ProofNode> = None;
        for (node, hash) in proof_data.iter().zip(hashes.iter()) {
            if let (Some(hash), Some(prev_node)) = (hash, prev_node) {
                builder.connect_hashes(prev_node.hash, *hash);
            }

            let node_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.to_vec());
            prev_node = Some(ProofNode::new(node_hash));
        }

        let proof_root = prev_node.expect("no root node was found in proof data");
        builder.connect_hashes(proof_root.hash, root_hash);

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
            let proof_node = slice_to_field_elements(proof_node);
            pw.set_target_arr(&targets.proof_data[i], &proof_node)?;
        }
        for (i, hash) in self.hashes.iter().enumerate() {
            if let (Some(hash_t), Some(hash)) = (targets.hashes[i], hash) {
                let hash = slice_to_hashout(hash);
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
