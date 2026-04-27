use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

use super::super::support::{I386Fixture, interpret_amd64_semantics};

const fn vec128(low: u64, high: u64) -> u128 {
    ((high as u128) << 64) | (low as u128)
}

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "movsd",
        instruction: "movsd xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xf2, 0x0f, 0x10, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movsd",
        instruction: "vmovsd xmm0, xmm2, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xeb, 0x10, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movsd",
        instruction: "movsd xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xf2, 0x0f, 0x10, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (
                    I386Register::Xmm0,
                    vec128(3.5f64.to_bits(), 0x1122_3344_5566_7788),
                ),
                (
                    I386Register::Xmm1,
                    vec128((-1.25f64).to_bits(), 0x99aa_bbcc_ddee_ff00),
                ),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn movsd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movsd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
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
