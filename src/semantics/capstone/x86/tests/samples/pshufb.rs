use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "pshufb",
        instruction: "pshufb xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x38, 0x00, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pshufb",
        instruction: "pshufb xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x38, 0x00, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (
                    I386Register::Xmm0,
                    vec128([
                        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd,
                        0xee, 0xff, 0x11, 0x22,
                    ]),
                ),
                (
                    I386Register::Xmm1,
                    vec128([
                        0x00, 0x81, 0x02, 0x83, 0x04, 0x85, 0x06, 0x87, 0x08, 0x89, 0x0a, 0x8b,
                        0x0c, 0x8d, 0x0e, 0x8f,
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
fn pshufb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn pshufb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
