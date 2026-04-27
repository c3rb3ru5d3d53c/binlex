use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
};
use crate::Architecture;

fn vec128(low: u64, high: u64) -> u128 {
    (u128::from(high) << 64) | u128::from(low)
}

#[test]
fn addsd_semantics_stay_complete() {
    assert_complete_semantics(
        "addsd xmm0, xmm1",
        Architecture::AMD64,
        &[0xf2, 0x0f, 0x58, 0xc1],
    );
}

#[test]
fn addsd_semantics_match_unicorn_transitions() {
    let lhs = 3.5f64.to_bits();
    let rhs = (-1.25f64).to_bits();
    let upper_a = 0x1122_3344_5566_7788u64;
    let upper_b = 0x99aa_bbcc_ddee_ff00u64;

    assert_amd64_semantics_match_unicorn(
        "addsd xmm0, xmm1",
        &[0xf2, 0x0f, 0x58, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Xmm0, vec128(lhs, upper_a)),
                (I386Register::Xmm1, vec128(rhs, upper_b)),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
