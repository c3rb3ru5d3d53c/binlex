use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
    interpret_amd64_semantics,
};
use crate::Architecture;

fn vec128(low: u64, high: u64) -> u128 {
    (u128::from(high) << 64) | u128::from(low)
}

#[test]
fn movsd_semantics_stay_complete() {
    let cases = [
        (
            "movsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x10, 0xc1],
        ),
        (
            "vmovsd xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xeb, 0x10, 0xc1],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn movsd_semantics_match_unicorn_transitions() {
    let lhs = 3.5f64.to_bits();
    let rhs = (-1.25f64).to_bits();
    let upper_a = 0x1122_3344_5566_7788u64;
    let upper_b = 0x99aa_bbcc_ddee_ff00u64;

    assert_amd64_semantics_match_unicorn(
        "movsd xmm0, xmm1",
        &[0xf2, 0x0f, 0x10, 0xc1],
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

// Unicorn 2.1.5 mis-models `vmovsd xmm0, xmm2, xmm1` for the tested VEX form:
// it zeroes the upper 64 bits of xmm0 instead of preserving them from the
// second source operand. Keep this as a semantics-only regression until we
// either confirm a Unicorn fix or switch this case to a different oracle.
#[test]
fn vmovsd_semantics_preserve_upper_lane_from_second_source() {
    let low_src = 0xbff4_0000_0000_0000u64;
    let upper_src = 0x1122_3344_5566_7788u64;
    let transition = interpret_amd64_semantics(
        "vmovsd xmm0, xmm2, xmm1",
        &[0xc5, 0xeb, 0x10, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Xmm0, 0),
                (I386Register::Xmm1, vec128(low_src, 0x99aa_bbcc_ddee_ff00)),
                (I386Register::Xmm2, vec128(0x400c_0000_0000_0000, upper_src)),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );

    let xmm0 = transition
        .post
        .registers
        .get("xmm0")
        .copied()
        .expect("xmm0 should be present");
    assert_eq!(
        xmm0,
        vec128(low_src, upper_src),
        "vmovsd semantics should take the low 64 bits from the third operand and preserve the upper 64 bits from the second operand"
    );
}
