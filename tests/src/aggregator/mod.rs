#![cfg(test)]

use plonky2::plonk::circuit_data::CircuitConfig;
pub mod aggregator_tests;
pub mod circuit_tests;

// TODO: Test against standard recursion config.
fn circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_zk_config()
}
