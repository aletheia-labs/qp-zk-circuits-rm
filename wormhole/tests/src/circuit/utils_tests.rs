use plonky2::field::types::Field;
use zk_circuits_common::circuit::F;
use zk_circuits_common::utils::{felts_to_u128, felts_to_u64, u128_to_felts, u64_to_felts};

// Helper to create F from a u64 for concise test cases
#[cfg(test)]
fn f(val: u64) -> F {
    F::from_noncanonical_u64(val)
}

#[test]
fn test_u128_to_felts_to_u128_round_trip() {
    // Test cases: zero, small, large, max u128, and random values
    let test_cases = [
        0u128,
        1u128,
        0x1234567890abcdefu128,
        u128::MAX,
        (1u128 << 96) - 1,            // Max value for high part
        (1u128 << 64) | 0xabcdefu128, // Mixed high and low
    ];

    for num in test_cases {
        // u128 -> Vec<F>
        let felts = u128_to_felts(num);
        assert_eq!(felts.len(), 4, "Expected exactly four field elements");

        // Vec<F> -> u128
        let round_trip_num = felts_to_u128(felts);

        // Check that the high and low parts match
        let expected_high = (num >> 64) as u64;
        let expected_low = num as u64;
        let expected = ((expected_high as u128) << 64) | (expected_low as u128);
        assert_eq!(
            round_trip_num, expected,
            "Round trip failed for input {}. Expected {}, got {}",
            num, expected, round_trip_num
        );
    }
}

#[test]
fn test_felts_to_u128_to_felts_round_trip() {
    // Test cases: various field element pairs within the field order
    let test_cases = [
        (f(0), f(0), f(0), f(0)),
        (f(1), f(1), f(1), f(1)),
        (f(0x1234567), f(0xabcdef), f(0x1234567), f(0xabcdef)),
        (
            f(u32::MAX as u64),
            f(u32::MAX as u64),
            f(u32::MAX as u64),
            f(u32::MAX as u64),
        ), // Max field element
        (f(0), f(u32::MAX as u64), f(0), f(u32::MAX as u64)), // Zero high, max low
        (f(u32::MAX as u64), f(0), f(u32::MAX as u64), f(0)), // Max high, zero low
    ];

    for (l3, l2, l1, l0) in test_cases {
        let felts = [l3, l2, l1, l0];

        // Vec<F> -> u128
        let num = felts_to_u128(felts);

        // u128 -> Vec<F>
        let round_trip_felts = u128_to_felts(num);
        assert_eq!(
            round_trip_felts, felts,
            "Round trip failed for input {:?}. Got {:?}",
            felts, round_trip_felts
        );
    }
}
#[test]
fn test_u64_to_felts_to_u64_round_trip() {
    // Test cases: zero, small, large, max u64, and random values
    let test_cases = [
        0u64,
        1u64,
        0x1234567890abcdefu64,
        u64::MAX,
        (1u64 << 32) - 1,           // Max value for high part
        (1u64 << 32) | 0xabcdefu64, // Mixed high and low
    ];

    for num in test_cases {
        // u64 -> Vec<F>
        let felts = u64_to_felts(num);
        assert_eq!(felts.len(), 2, "Expected exactly two field elements");

        // Vec<F> -> u64
        let round_trip_num = felts_to_u64(felts);

        // Check that the high and low parts match
        let expected_high = num >> 32;
        let expected_low = num;
        let expected = (expected_high << 32) | expected_low;
        assert_eq!(
            round_trip_num, expected,
            "Round trip failed for input {}. Expected {}, got {}",
            num, expected, round_trip_num
        );
    }
}

#[test]
fn test_felts_to_u64_to_felts_round_trip() {
    // Test cases: various field element pairs within the field order
    let test_cases = [
        (f(0), f(0)),                             // Zero
        (f(1), f(1)),                             // One
        (f(0x12345678), f(0x9abcdef0)),           // Mixed values
        (f(u32::MAX as u64), f(u32::MAX as u64)), // Max field element
        (f(0), f(u32::MAX as u64)),               // Zero high, max low
        (f(u32::MAX as u64), f(0)),               // Max high, zero low
    ];

    for (l1, l0) in test_cases {
        let felts = [l1, l0];

        // Vec<F> -> u64
        let num = felts_to_u64(felts);

        // u64 -> Vec<F>
        let round_trip_felts = u64_to_felts(num);
        assert_eq!(
            round_trip_felts, felts,
            "Round trip failed for input {:?}. Got {:?}",
            felts, round_trip_felts
        );
    }
}
#[test]
fn test_edge_cases() {
    // Test specific edge cases
    let num = u128::MAX;
    let felts = u128_to_felts(num);
    assert_eq!(felts.len(), 4);
    let result = felts_to_u128(felts);
    let expected_l3 = (u128::MAX >> 96) as u64;
    let expected_l2 = (u128::MAX >> 64) as u64;
    let expected_l1 = (u128::MAX >> 32) as u64;
    let expected_l0 = (u128::MAX) as u64;
    let expected = ((expected_l3 as u128) << 96)
        | ((expected_l2 as u128) << 64)
        | ((expected_l1 as u128) << 32)
        | (expected_l0 as u128);
    assert_eq!(result, expected);

    // Test zero
    let num = 0u128;
    let felts = u128_to_felts(num);
    assert_eq!(felts, [f(0), f(0), f(0), f(0)]);
    let result = felts_to_u128(felts);
    assert_eq!(result, 0);
}
