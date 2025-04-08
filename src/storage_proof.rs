use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
};

use crate::{CircuitFragment, D, F};

struct ProofNode {
    hash: HashOutTarget,
    index: usize,
}

impl ProofNode {
    pub fn new(hash: HashOutTarget, index: usize) -> Self {
        ProofNode { hash, index }
    }
}

pub struct StorageProofInputs {
    root_hash: [u8; 32],
    proof_data: Vec<Vec<u8>>,
}

pub struct StorageProofTargets {
    root_hash: HashOutTarget,
    proof_data: Vec<Vec<Target>>,
}

pub struct StorageProof {
    hash_indexes: Vec<usize>,
}

impl CircuitFragment for StorageProof {
    type PrivateInputs = StorageProofInputs;
    type Targets = StorageProofTargets;

    fn circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> Self::Targets {
        let root_hash = builder.add_virtual_hash_public_input();
        let num_nodes = self.hash_indexes.len();
        let mut proof_data = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            let node = builder.add_virtual_targets(num_nodes);
            proof_data.push(node);
        }

        // Setup constraints.
        let mut prev_node: Option<ProofNode> = None;
        for (node, hash_index) in proof_data.iter().zip(&self.hash_indexes) {
            if let Some(prev) = prev_node {
                // TODO: Find node hash in parents raw bytes using the provided index.
                let indexed_bytes = &node[prev.index..(prev.index + 32)];
                let stored_child_hash = HashOutTarget::from_vec(indexed_bytes.to_vec());
                builder.connect_hashes(stored_child_hash, prev.hash);
            }

            let node_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.to_vec());
            prev_node = Some(ProofNode::new(node_hash, *hash_index));
        }

        let proof_root = prev_node.expect("no root node was found in proof data");
        builder.connect_hashes(proof_root.hash, root_hash);

        StorageProofTargets {
            root_hash,
            proof_data,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.root_hash, bytes32_to_hashout(inputs.root_hash))?;
        for (i, proof_node) in inputs.proof_data.into_iter().enumerate() {
            let proof_node: Vec<F> = proof_node
                .iter()
                .map(|&byte| F::from_canonical_u8(byte))
                .collect();
            pw.set_target_arr(&targets.proof_data[i], &proof_node)?;
        }

        Ok(())
    }
}

fn bytes32_to_hashout(bytes: [u8; 32]) -> HashOut<F> {
    use std::convert::TryInto;

    let elements = (0..4)
        .map(|i| {
            let chunk: [u8; 8] = bytes[i * 8..(i + 1) * 8].try_into().unwrap();
            F::from_canonical_u64(u64::from_le_bytes(chunk))
        })
        .collect::<Vec<_>>();

    HashOut {
        elements: elements.try_into().unwrap(),
    }
}
