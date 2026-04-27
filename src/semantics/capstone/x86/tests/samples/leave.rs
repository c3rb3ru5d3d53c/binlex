use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
};
use crate::Architecture;

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "leave",
    instruction: "leave",
    architecture: Architecture::I386,
    bytes: &[0xc9],
    expected_status: None,
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
        eflags: 1 << 1,
        memory: &[(0x2800, &[0x44, 0x33, 0x22, 0x11])],
    }),
    roundtrip_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0x1122_3344),
            (I386Register::Ebx, 0x5566_7788),
            (I386Register::Ecx, 0x99aa_bbcc),
            (I386Register::Edx, 0xddee_ff00),
            (I386Register::Esi, 0x1234_5678),
            (I386Register::Edi, 0x8765_4321),
            (I386Register::Ebp, 0x2fe0),
            (I386Register::Esp, 0x2fd0),
        ],
        eflags: 0x246,
        memory: &[(0x2fe0, &[0xf0, 0x2f, 0x00, 0x00])],
    }),
}];

#[test]
fn leave_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn leave_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
