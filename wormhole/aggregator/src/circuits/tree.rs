use anyhow::bail;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputsTarget,
    },
};
use wormhole_verifier::{ProofWithPublicInputs, WormholeVerifier};
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

use crate::circuits::DUMMY_PROOF_BYTES;

#[derive(Debug, Clone)]
pub struct TreeAggregatorTargets<const N: usize> {
    verifier_data: VerifierCircuitTarget,
    proofs: [ProofWithPublicInputsTarget<D>; N],
    // HACK: This allows us to only create `circuit_data` once.
    circuit_data: CommonCircuitData<F, D>,
}

impl<const N: usize> TreeAggregatorTargets<N> {
    pub fn new(builder: &mut CircuitBuilder<F, D>, config: CircuitConfig) -> Self {
        let circuit_data = WormholeVerifier::new(config, None).circuit_data.common;
        let verifier_data =
            builder.add_virtual_verifier_data(circuit_data.fri_params.config.cap_height);

        // Setup targets for proofs.
        let mut proofs = Vec::with_capacity(N);
        for _ in 0..N {
            proofs.push(builder.add_virtual_proof_with_pis(&circuit_data));
        }

        let proofs: [ProofWithPublicInputsTarget<D>; N] =
            std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&circuit_data));

        Self {
            verifier_data,
            proofs,
            circuit_data,
        }
    }
}

pub struct TreeAggregator<const N: usize> {
    pub inner_verifier: WormholeVerifier,
    num_proofs: usize,
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
}

impl<const N: usize> TreeAggregator<N> {
    pub fn new(config: CircuitConfig) -> Self {
        let inner_verifier = WormholeVerifier::new(config, None);
        Self {
            inner_verifier,
            num_proofs: 0,
            proofs: Vec::with_capacity(N),
        }
    }

    pub fn set_proofs(
        &mut self,
        proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<()> {
        let num_proofs = proofs.len();

        if num_proofs > N {
            bail!("proofs to aggregate was more than the maximum allowed")
        }

        // Move proof data from the aggregater, to be used the circuit.
        self.num_proofs = num_proofs;
        self.proofs = proofs;

        let dummy_proof = ProofWithPublicInputs::from_bytes(
            DUMMY_PROOF_BYTES.to_vec(),
            &self.inner_verifier.circuit_data.common,
        )?;
        for _ in 0..(N - num_proofs) {
            self.proofs.push(dummy_proof.clone());
        }

        Ok(())
    }
}

impl<const N: usize> CircuitFragment for TreeAggregator<N> {
    type Targets = TreeAggregatorTargets<N>;

    fn circuit(
        Self::Targets {
            verifier_data,
            proofs,
            circuit_data,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Verify each aggregated proof separately.
        for proof in proofs {
            builder.verify_proof::<C>(proof, verifier_data, circuit_data);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        for (proof_target, proof) in targets.proofs.iter().zip(self.proofs.iter()) {
            pw.set_proof_with_pis_target(proof_target, proof)?;
        }

        pw.set_verifier_data_target(
            &targets.verifier_data,
            &self.inner_verifier.circuit_data.verifier_only,
        )
    }
}

#[allow(dead_code)]
fn aggregate_to_tree(
    mut proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    leaf_circuit_data: &CircuitData<F, C, D>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    while proofs.len() > 1 {
        let mut aggregated_proofs = Vec::with_capacity(proofs.len() / 2);

        for pair in proofs.chunks(2) {
            let aggregated_proof = aggregate_pair(
                &pair[0],
                &pair[1],
                &leaf_circuit_data.common,
                &leaf_circuit_data.verifier_only,
            )?;
            aggregated_proofs.push(aggregated_proof);
        }

        proofs = aggregated_proofs;
    }

    assert!(proofs.len() == 1);
    Ok(proofs.pop().unwrap())
}

#[allow(dead_code)]
/// Circuit gadget that takes in a pair of proofs, a and b, aggregates it and return the new proof.
fn aggregate_pair(
    a: &ProofWithPublicInputs<F, C, D>,
    b: &ProofWithPublicInputs<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut builder = CircuitBuilder::new(common_data.config.clone());
    let verifier_data_t =
        builder.add_virtual_verifier_data(common_data.fri_params.config.cap_height);

    // Verify a.
    let proof_a = builder.add_virtual_proof_with_pis(common_data);
    builder.verify_proof::<C>(&proof_a, &verifier_data_t, common_data);

    // Verify b.
    let proof_b = builder.add_virtual_proof_with_pis(common_data);
    builder.verify_proof::<C>(&proof_b, &verifier_data_t, common_data);

    let data = builder.build();

    // Fill targets.
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_data_t, verifier_data)?;
    pw.set_proof_with_pis_target(&proof_a, a)?;
    pw.set_proof_with_pis_target(&proof_b, b)?;

    let aggregated_proof = data.prove(pw)?;
    Ok(aggregated_proof)
}
