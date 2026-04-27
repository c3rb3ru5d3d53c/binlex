use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsb",
        architecture: Architecture::I386,
        bytes: &[0xac],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xad],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsd",
        architecture: Architecture::I386,
        bytes: &[0xad],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsq",
        architecture: Architecture::AMD64,
        bytes: &[0x48, 0xad],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsb",
        architecture: Architecture::I386,
        bytes: &[0xac],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3300),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3300, &[0xaa])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xad],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3310),
            ],
            eflags: 1 << 1,
            memory: &[(0x3310, &[0xef, 0xbe])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsd",
        architecture: Architecture::I386,
        bytes: &[0xad],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Eax, 0), (I386Register::Esi, 0x3320)],
            eflags: 1 << 1,
            memory: &[(0x3320, &[0x44, 0x33, 0x22, 0x11])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsb",
        architecture: Architecture::I386,
        bytes: &[0xac],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3300),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3300, &[0xaa])],
        }),
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xad],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3310),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3310, &[0xef, 0xbe])],
        }),
    },
    X86Sample {
        mnemonic: "lods",
        instruction: "lodsd",
        architecture: Architecture::I386,
        bytes: &[0xad],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x0000_0000),
                (I386Register::Esi, 0x3320),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3320, &[0x44, 0x33, 0x22, 0x11])],
        }),
    },
];

#[test]
fn lods_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn lods_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn lods_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
