use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
};
use crate::Architecture;

#[test]
fn cvtdq2pd_semantics_stay_complete() {
    assert_complete_semantics(
        "cvtdq2pd xmm0, xmm1",
        Architecture::AMD64,
        &[0xf3, 0x0f, 0xe6, 0xc1],
    );
}

#[test]
fn cvtdq2pd_semantics_match_unicorn_transitions() {
    let int_pairs = (10u128) | (u128::from((-2i32 as u32) as u64) << 32);

    assert_amd64_semantics_match_unicorn(
        "cvtdq2pd xmm0, xmm1",
        &[0xf3, 0x0f, 0xe6, 0xc1],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, int_pairs)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
