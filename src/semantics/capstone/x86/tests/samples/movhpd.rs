use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

const MEM64: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76];

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "movhpd",
    instruction: "movhpd xmm0, qword ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x16, 0x00],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Rax, 0x3000),
            (
                I386Register::Xmm0,
                vec128([
                    0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                    0xff, 0x11, 0x22,
                ]),
            ),
        ],
        eflags: 1 << 1,
        memory: &[(0x3000, MEM64)],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn movhpd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movhpd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
