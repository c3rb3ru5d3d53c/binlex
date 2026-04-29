use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsb",
        architecture: Architecture::I386,
        bytes: &[0xa6],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xa7],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsd",
        architecture: Architecture::I386,
        bytes: &[0xa7],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsq",
        architecture: Architecture::AMD64,
        bytes: &[0x48, 0xa7],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsb",
        architecture: Architecture::I386,
        bytes: &[0xa6],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esi, 0x3500), (I386Register::Edi, 0x3600)],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3500, &[0x20]), (0x3600, &[0x10])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xa7],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esi, 0x3510), (I386Register::Edi, 0x3610)],
            eflags: 1 << 1,
            memory: &[(0x3510, &[0x34, 0x12]), (0x3610, &[0x35, 0x12])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsd",
        architecture: Architecture::I386,
        bytes: &[0xa7],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esi, 0x3520), (I386Register::Edi, 0x3620)],
            eflags: 1 << 1,
            memory: &[
                (0x3520, &[0x78, 0x56, 0x34, 0x12]),
                (0x3620, &[0x77, 0x56, 0x34, 0x12]),
            ],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsb",
        architecture: Architecture::I386,
        bytes: &[0xa6],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3500),
                (I386Register::Edi, 0x3600),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3500, &[0x20]), (0x3600, &[0x10])],
        }),
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xa7],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3510),
                (I386Register::Edi, 0x3610),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3510, &[0x34, 0x12]), (0x3610, &[0x35, 0x12])],
        }),
    },
    X86Sample {
        mnemonic: "cmps",
        instruction: "cmpsd",
        architecture: Architecture::I386,
        bytes: &[0xa7],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3520),
                (I386Register::Edi, 0x3620),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[
                (0x3520, &[0x78, 0x56, 0x34, 0x12]),
                (0x3620, &[0x77, 0x56, 0x34, 0x12]),
            ],
        }),
    },
];

#[test]
fn cmps_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmps_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn cmps_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
