use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "sub",
    instruction: "sub eax, ebx",
    architecture: Architecture::I386,
    bytes: &[0x29, 0xd8],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0x0000_0000),
            (I386Register::Ebx, 0x0000_0001),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0x1122_3344),
            (I386Register::Ebx, 0x0102_0304),
            (I386Register::Ecx, 0x99aa_bbcc),
            (I386Register::Edx, 0xddee_ff00),
            (I386Register::Esi, 0x1234_5678),
            (I386Register::Edi, 0x8765_4321),
            (I386Register::Ebp, 0x2ff0),
            (I386Register::Esp, 0x2ff0),
        ],
        eflags: 0x202,
        memory: &[],
    }),
}];

#[test]
fn sub_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sub_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn sub_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
