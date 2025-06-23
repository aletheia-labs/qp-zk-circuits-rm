use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CommonCircuitData;
use wormhole_aggregator::aggregator::WormholeProofAggregator;
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof_zk.bin");

// A macro for creating an aggregation benchmark with a specified number of proofs to
// aggregate. The number of proofs is expected to be some constant, N, that can be expressed as `2^M`.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $num_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            const N: usize = $num_proofs;

            // Setup proofs.
            let proofs = {
                let temp_aggregator = WormholeProofAggregator::<N>::default();
                deserialize_proofs::<N>(&temp_aggregator.leaf_circuit_data.common)
            };

            c.bench_function(
                &format!("aggregate_proofs_{}", stringify!($num_proofs)),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator = WormholeProofAggregator::<N>::default();
                            for proof in proofs.clone() {
                                aggregator.push_proof(proof).unwrap();
                            }
                            aggregator
                        },
                        |mut aggregator| {
                            aggregator.aggregate().unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

fn deserialize_proofs<const N: usize>(
    common_data: &CommonCircuitData<F, D>,
) -> [ProofWithPublicInputs<F, C, D>; N] {
    let proof = ProofWithPublicInputs::from_bytes(DUMMY_PROOF_BYTES.to_vec(), common_data).unwrap();
    std::array::from_fn(|_| proof.clone())
}

// Various proof sizes.
aggregate_proofs_benchmark!(bench_aggregate_2_proofs, 2);
aggregate_proofs_benchmark!(bench_aggregate_4_proofs, 4);
aggregate_proofs_benchmark!(bench_aggregate_8_proofs, 8);
aggregate_proofs_benchmark!(bench_aggregate_16_proofs, 16);
aggregate_proofs_benchmark!(bench_aggregate_32_proofs, 32);

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10);
    targets = bench_aggregate_2_proofs, bench_aggregate_4_proofs, bench_aggregate_8_proofs, bench_aggregate_16_proofs, bench_aggregate_32_proofs
);
criterion_main!(benches);
