use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "pop",
        instruction: "popal",
        architecture: Architecture::I386,
        bytes: &[0x61],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "popfd",
        architecture: Architecture::I386,
        bytes: &[0x9d],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "popfq",
        architecture: Architecture::AMD64,
        bytes: &[0x9d],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "pop eax",
        architecture: Architecture::I386,
        bytes: &[0x58],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Eax, 0xdead_beef), (I386Register::Esp, 0x2800)],
            eflags: 1 << 1,
            memory: &[(0x2800, &[0x78, 0x56, 0x34, 0x12])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "popal",
        architecture: Architecture::I386,
        bytes: &[0x61],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0),
                (I386Register::Edx, 0),
                (I386Register::Ebx, 0),
                (I386Register::Esp, 0x2800),
                (I386Register::Ebp, 0),
                (I386Register::Esi, 0),
                (I386Register::Edi, 0),
            ],
            eflags: 1 << 1,
            memory: &[(
                0x2800,
                &[
                    0x77, 0x77, 0x77, 0x77, 0x66, 0x66, 0x66, 0x66, 0x55, 0x55, 0x55, 0x55,
                    0x40, 0x28, 0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x33, 0x33, 0x33, 0x33,
                    0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11,
                ],
            )],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "popfd",
        architecture: Architecture::I386,
        bytes: &[0x9d],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esp, 0x2800)],
            eflags: 1 << 1,
            memory: &[(0x2800, &[0x35, 0x06, 0x00, 0x00])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "pop eax",
        architecture: Architecture::I386,
        bytes: &[0x58],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x246,
            memory: &[(0x2fec, &[0x78, 0x56, 0x34, 0x12])],
        }),
    },
    X86Sample {
        mnemonic: "pop",
        instruction: "popfd",
        architecture: Architecture::I386,
        bytes: &[0x9d],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x202,
            memory: &[(0x2fec, &[0x46, 0x02, 0x00, 0x00])],
        }),
    },
];

#[test]
fn pop_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn pop_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn pop_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
