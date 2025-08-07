use anyhow::{bail, Context};
use plonky2::plonk::circuit_data::CommonCircuitData;
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

pub fn pad_with_dummy_proofs(
    mut proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    proof_len: usize,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>> {
    let num_proofs = proofs.len();

    if num_proofs > proof_len {
        bail!("proofs to aggregate was more than the maximum allowed")
    }

    // read in the dummy proof bytes from the path "../aggregator/data/dummy_proof_zk.bin"
    let path = if cfg!(feature = "no_zk") {
        "../aggregator/data/dummy_proof.bin"
    } else {
        "../aggregator/data/dummy_proof_zk.bin"
    };
    let dummy_proof_bytes =
        std::fs::read(path).context("failed to read dummy proof bytes from file")?;

    let dummy_proof = ProofWithPublicInputs::from_bytes(dummy_proof_bytes, common_data)
        .context("failed to deserialize dummy proof")?;
    for _ in 0..(proof_len - num_proofs) {
        proofs.push(dummy_proof.clone());
    }

    Ok(proofs)
}
