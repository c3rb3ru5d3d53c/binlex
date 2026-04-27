use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "push",
        instruction: "pushal",
        architecture: Architecture::I386,
        bytes: &[0x60],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "push",
        instruction: "pushfd",
        architecture: Architecture::I386,
        bytes: &[0x9c],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "push",
        instruction: "pushfq",
        architecture: Architecture::AMD64,
        bytes: &[0x9c],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "push",
        instruction: "push eax",
        architecture: Architecture::I386,
        bytes: &[0x50],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Esp, 0x2800),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "push",
        instruction: "pushal",
        architecture: Architecture::I386,
        bytes: &[0x60],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1111_1111),
                (I386Register::Ecx, 0x2222_2222),
                (I386Register::Edx, 0x3333_3333),
                (I386Register::Ebx, 0x4444_4444),
                (I386Register::Esp, 0x2840),
                (I386Register::Ebp, 0x5555_5555),
                (I386Register::Esi, 0x6666_6666),
                (I386Register::Edi, 0x7777_7777),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "push",
        instruction: "pushfd",
        architecture: Architecture::I386,
        bytes: &[0x9c],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esp, 0x2800)],
            eflags: (1 << 1) | (1 << 0) | (1 << 2) | (1 << 9) | (1 << 10),
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "push",
        instruction: "push eax",
        architecture: Architecture::I386,
        bytes: &[0x50],
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
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: &[(0x2fec, &[0xaa, 0xbb, 0xcc, 0xdd])],
        }),
    },
    X86Sample {
        mnemonic: "push",
        instruction: "pushfd",
        architecture: Architecture::I386,
        bytes: &[0x9c],
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
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: &[(0x2fec, &[0xaa, 0xbb, 0xcc, 0xdd])],
        }),
    },
];

#[test]
fn push_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn push_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn push_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
