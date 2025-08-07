#![cfg(test)]
use wormhole_aggregator::aggregator::WormholeProofAggregator;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

use crate::aggregator::circuit_config;
use test_helpers::storage_proof::TestInputs;

#[test]
fn push_proof_to_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());
    aggregator.push_proof(proof).unwrap();

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), 1);
}

#[test]
fn push_proof_to_full_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());

    // Fill up the proof buffer.
    for _ in 0..aggregator.config.num_leaf_proofs {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let result = aggregator.push_proof(proof.clone());
    assert!(result.is_err());

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), aggregator.config.num_leaf_proofs);
}

#[test]
fn aggregate_single_proof() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    // Make sure directory exists
    std::fs::create_dir_all("../aggregator/data").unwrap();

    // Write to ../aggregator/data/dummy_proof_zk.bin if cfg feature = "no_zk" then write to ../aggregator/data/dummy_proof.bin
    #[cfg(feature = "no_zk")]
    let out_path = "../aggregator/data/dummy_proof.bin";
    #[cfg(not(feature = "no_zk"))]
    let out_path = "../aggregator/data/dummy_proof_zk.bin";
    println!("Writing dummy proof to: {}", out_path);
    std::fs::write(out_path, proof.to_bytes()).expect("Failed to write dummy proof");

    // Just a safety check
    assert!(std::path::Path::new(out_path).exists());

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());
    aggregator.push_proof(proof).unwrap();

    aggregator.aggregate().unwrap();
}

#[test]
fn aggregate_proofs_into_tree() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());

    // Fill up the proof buffer.
    for _ in 0..aggregator.config.num_leaf_proofs {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let aggregated_proof = aggregator.aggregate().unwrap();
    aggregated_proof
        .circuit_data
        .verify(aggregated_proof.proof)
        .unwrap();
}

#[test]
fn aggregate_half_full_proof_array_into_tree() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());

    // Fill up the proof buffer.
    for _ in 0..aggregator.config.num_leaf_proofs {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let aggregated_proof = aggregator.aggregate().unwrap();
    aggregated_proof
        .circuit_data
        .verify(aggregated_proof.proof)
        .unwrap();
}
