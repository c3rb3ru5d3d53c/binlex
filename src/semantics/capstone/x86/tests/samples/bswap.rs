use super::super::support::{
    I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "bswap",
    instruction: "bswap eax",
    architecture: Architecture::I386,
    bytes: &[0x0f, 0xc8],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Eax, 0x1234_5678)],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn bswap_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bswap_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn bswap_roundtrip_i386_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bswap eax",
        &[0x0f, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn bswap_roundtrip_amd64_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bswap rax",
        &[0x48, 0x0f, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x247,
            memory: vec![],
        },
    );
}
