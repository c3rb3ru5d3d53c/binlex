use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "stos",
        instruction: "stosb",
        architecture: Architecture::I386,
        bytes: &[0xaa],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosd",
        architecture: Architecture::I386,
        bytes: &[0xab],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosq",
        architecture: Architecture::AMD64,
        bytes: &[0x48, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "rep stosd",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "rep stosw",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0x66, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosb",
        architecture: Architecture::I386,
        bytes: &[0xaa],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_00ab),
                (I386Register::Edi, 0x3000),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xab],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_cdef),
                (I386Register::Edi, 0x3010),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosd",
        architecture: Architecture::I386,
        bytes: &[0xab],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3020),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "rep stosd",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xab],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edi, 0x3700),
                (I386Register::Ecx, 2),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "rep stosw",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0x66, 0xab],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_abcd),
                (I386Register::Edi, 0x3710),
                (I386Register::Ecx, 2),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosb",
        architecture: Architecture::I386,
        bytes: &[0xaa],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_00ab),
                (I386Register::Edi, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3000, &[0x00])],
        }),
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xab],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_cdef),
                (I386Register::Edi, 0x3010),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3010, &[0x00, 0x00])],
        }),
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "stosd",
        architecture: Architecture::I386,
        bytes: &[0xab],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3020),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3020, &[0x00, 0x00, 0x00, 0x00])],
        }),
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "rep stosw",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0x66, 0xab],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_abcd),
                (I386Register::Edi, 0x3710),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x370c, &[0x00, 0x00, 0x00, 0x00])],
        }),
    },
    X86Sample {
        mnemonic: "stos",
        instruction: "rep stosd",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xab],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edi, 0x3700),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3700, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        }),
    },
];

#[test]
fn stos_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn stos_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn stos_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
