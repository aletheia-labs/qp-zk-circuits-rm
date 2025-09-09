use al_wormhole_circuit_builder::generate_circuit_binaries;
use anyhow::Result;

fn main() -> Result<()> {
    generate_circuit_binaries("generated-bins", true)
}
