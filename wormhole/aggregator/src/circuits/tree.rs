use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::GenericConfig,
    },
};
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

use crate::TREE_BRANCHING_FACTOR;

/// A proof containing both the proof data and the circuit data needed to verify it.
#[derive(Debug)]
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
}

pub fn aggregate_to_tree(
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<AggregatedProof<F, C, D>> {
    // Aggregate the first level.
    let mut proofs = aggregate_level(leaf_proofs, common_data, verifier_data)?;

    // Do the next levels by utilizing the circuit data within each aggregated proof.
    while proofs.len() > 1 {
        let common_data = &proofs[0].circuit_data.common.clone();
        let verifier_data = &proofs[0].circuit_data.verifier_only.clone();
        let to_aggregate = proofs.into_iter().map(|p| p.proof).collect();

        let aggregated_proofs = aggregate_level(to_aggregate, common_data, verifier_data)?;

        proofs = aggregated_proofs;
    }

    assert!(proofs.len() == 1);
    Ok(proofs.pop().unwrap())
}

fn aggregate_level(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<Vec<AggregatedProof<F, C, D>>> {
    let mut aggregated_proofs = Vec::with_capacity(proofs.len() / TREE_BRANCHING_FACTOR);

    for pair in proofs.chunks(TREE_BRANCHING_FACTOR) {
        let proof_a = &pair[0];
        let proof_b = &pair[1];

        let aggregated_proof = aggregate_pair(proof_a, proof_b, common_data, verifier_data)?;
        aggregated_proofs.push(aggregated_proof);
    }

    Ok(aggregated_proofs)
}

/// Circuit gadget that takes in a pair of proofs, a and b, aggregates it and return the new proof.
fn aggregate_pair(
    a: &ProofWithPublicInputs<F, C, D>,
    b: &ProofWithPublicInputs<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<AggregatedProof<F, C, D>> {
    let mut builder = CircuitBuilder::new(common_data.config.clone());
    let verifier_data_t =
        builder.add_virtual_verifier_data(common_data.fri_params.config.cap_height);

    // Verify a.
    let proof_a = builder.add_virtual_proof_with_pis(common_data);
    builder.verify_proof::<C>(&proof_a, &verifier_data_t, common_data);

    // Verify b.
    let proof_b = builder.add_virtual_proof_with_pis(common_data);
    builder.verify_proof::<C>(&proof_b, &verifier_data_t, common_data);

    // Aggregate public inputs of proofs.
    builder.register_public_inputs(&proof_a.public_inputs);
    builder.register_public_inputs(&proof_b.public_inputs);

    let circuit_data = builder.build();

    // Fill targets.
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_data_t, verifier_data)?;
    pw.set_proof_with_pis_target(&proof_a, a)?;
    pw.set_proof_with_pis_target(&proof_b, b)?;

    let proof = circuit_data.prove(pw)?;

    let aggregated_proof = AggregatedProof {
        proof,
        circuit_data,
    };
    Ok(aggregated_proof)
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
        },
    };
    use zk_circuits_common::circuit::{C, D, F};

    use crate::circuits::tree::{aggregate_pair, aggregate_to_tree, AggregatedProof};

    fn generate_base_circuit() -> (CircuitData<F, C, D>, Target) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let x_sq = builder.mul(x, x);
        builder.register_public_input(x_sq);

        let data = builder.build::<C>();
        (data, x)
    }

    fn prove_square(value: F) -> AggregatedProof<F, C, D> {
        let (circuit_data, target) = generate_base_circuit();

        let mut pw = PartialWitness::new();
        pw.set_target(target, value).unwrap();
        let proof = circuit_data.prove(pw).unwrap();

        AggregatedProof {
            proof,
            circuit_data,
        }
    }

    #[test]
    fn recursive_aggregation_tree() {
        // Generate multiple leaf proofs.
        let inputs = [
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
            F::from_canonical_u64(5),
            F::from_canonical_u64(6),
        ];
        let proofs = inputs.iter().map(|&v| prove_square(v)).collect::<Vec<_>>();

        let common_data = &proofs[0].circuit_data.common.clone();
        let verifier_data = &proofs[0].circuit_data.verifier_only.clone();
        let to_aggregate = proofs.into_iter().map(|p| p.proof).collect();

        // Aggregate into tree.
        let root_proof = aggregate_to_tree(to_aggregate, common_data, verifier_data).unwrap();

        // Verify final root proof.
        root_proof.circuit_data.verify(root_proof.proof).unwrap()
    }

    #[test]
    fn pair_aggregation() {
        let proof1 = prove_square(F::from_canonical_u64(7));
        let proof2 = prove_square(F::from_canonical_u64(8));

        let aggregated = aggregate_pair(
            &proof1.proof,
            &proof2.proof,
            &proof1.circuit_data.common,
            &proof1.circuit_data.verifier_only,
        )
        .unwrap();

        aggregated.circuit_data.verify(aggregated.proof).unwrap();
    }
}
