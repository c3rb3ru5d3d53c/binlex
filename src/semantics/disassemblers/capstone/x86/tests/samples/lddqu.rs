use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const MEM128: &[u8] = &[
    0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57, 0x9b, 0xdf,
];

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "lddqu",
    instruction: "lddqu xmm0, xmmword ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0xf2, 0x0f, 0xf0, 0x00],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Rax, 0x3000), (I386Register::Xmm0, 0)],
        eflags: 1 << 1,
        memory: &[(0x3000, MEM128)],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn lddqu_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn lddqu_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
