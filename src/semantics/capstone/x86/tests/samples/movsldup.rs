use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "movsldup",
        instruction: "movsldup xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xf3, 0x0f, 0x12, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movsldup",
        instruction: "movsldup xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xf3, 0x0f, 0x12, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Xmm0, 0),
                (
                    I386Register::Xmm1,
                    vec128([
                        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22,
                        0x11, 0x00, 0x99, 0x88,
                    ]),
                ),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn movsldup_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movsldup_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
