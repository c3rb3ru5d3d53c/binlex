use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "scas",
        instruction: "scasb",
        architecture: Architecture::I386,
        bytes: &[0xae],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xaf],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasd",
        architecture: Architecture::I386,
        bytes: &[0xaf],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasq",
        architecture: Architecture::AMD64,
        bytes: &[0x48, 0xaf],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasb",
        architecture: Architecture::I386,
        bytes: &[0xae],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_0041),
                (I386Register::Edi, 0x3400),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3400, &[0x41])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xaf],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_1234),
                (I386Register::Edi, 0x3410),
            ],
            eflags: 1 << 1,
            memory: &[(0x3410, &[0x34, 0x12])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasd",
        architecture: Architecture::I386,
        bytes: &[0xaf],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3420),
            ],
            eflags: 1 << 1,
            memory: &[(0x3420, &[0x79, 0x56, 0x34, 0x12])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasb",
        architecture: Architecture::I386,
        bytes: &[0xae],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_0041),
                (I386Register::Edi, 0x3400),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3400, &[0x41])],
        }),
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xaf],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_1234),
                (I386Register::Edi, 0x3410),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3410, &[0x34, 0x12])],
        }),
    },
    X86Sample {
        mnemonic: "scas",
        instruction: "scasd",
        architecture: Architecture::I386,
        bytes: &[0xaf],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3420),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3420, &[0x79, 0x56, 0x34, 0x12])],
        }),
    },
];

#[test]
fn scas_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn scas_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn scas_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
