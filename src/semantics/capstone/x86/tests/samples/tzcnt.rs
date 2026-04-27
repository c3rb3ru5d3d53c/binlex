use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "tzcnt",
    instruction: "tzcnt ecx, eax",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0xbc, 0xc8],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn tzcnt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn tzcnt_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
