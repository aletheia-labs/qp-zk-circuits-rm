use std::path::PathBuf;

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
        bail!("proofs to aggregate was more than the maximum allowed");
    }

    if num_proofs == proof_len {
        return Ok(proofs);
    }

    // Resolve relative to crate root using CARGO_MANIFEST_DIR
    let file_name = if cfg!(feature = "no_zk") {
        "dummy_proof.bin"
    } else {
        "dummy_proof_zk.bin"
    };

    let dummy_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "aggregator",
        "data",
        file_name,
    ]
    .iter()
    .collect();

    let dummy_proof_bytes = std::fs::read(&dummy_path).with_context(|| {
        format!(
            "failed to read dummy proof bytes from path: {}",
            dummy_path.display()
        )
    })?;

    let dummy_proof = ProofWithPublicInputs::from_bytes(dummy_proof_bytes, common_data)
        .context("failed to deserialize dummy proof")?;
    for _ in 0..(proof_len - num_proofs) {
        proofs.push(dummy_proof.clone());
    }

    Ok(proofs)
}
