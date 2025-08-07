use plonky2::plonk::circuit_data::CircuitConfig;
use test_helpers::storage_proof::TestInputs;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

fn main() {
    let prover = WormholeProver::new(CircuitConfig::standard_recursion_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    #[cfg(not(feature = "no_zk"))]
    const DUMMY_PROOF_PATH: &str = "wormhole/aggregator/data/dummy_proof_zk.bin";
    #[cfg(feature = "no_zk")]
    const DUMMY_PROOF_PATH: &str = "wormhole/aggregator/data/dummy_proof.bin";
    std::fs::create_dir_all("wormhole/aggregator/data").unwrap();
    let out_path = DUMMY_PROOF_PATH;
    println!("Writing dummy proof to: {}", out_path);
    std::fs::write(out_path, proof.to_bytes()).expect("Failed to write dummy proof");
}
