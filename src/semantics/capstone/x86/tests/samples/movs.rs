use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "movs",
        instruction: "movsb",
        architecture: Architecture::I386,
        bytes: &[0xa4],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xa5],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsd",
        architecture: Architecture::I386,
        bytes: &[0xa5],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsq",
        architecture: Architecture::AMD64,
        bytes: &[0x48, 0xa5],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsb",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xa4],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsw",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0x66, 0xa5],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsd",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xa5],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsq",
        architecture: Architecture::AMD64,
        bytes: &[0xf3, 0x48, 0xa5],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsb",
        architecture: Architecture::I386,
        bytes: &[0xa4],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esi, 0x3100), (I386Register::Edi, 0x3200)],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3100, &[0x41])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xa5],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esi, 0x3110), (I386Register::Edi, 0x3210)],
            eflags: 1 << 1,
            memory: &[(0x3110, &[0x34, 0x12])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsd",
        architecture: Architecture::I386,
        bytes: &[0xa5],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esi, 0x3120), (I386Register::Edi, 0x3220)],
            eflags: 1 << 1,
            memory: &[(0x3120, &[0x78, 0x56, 0x34, 0x12])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsb",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xa4],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3800),
                (I386Register::Edi, 0x3900),
                (I386Register::Ecx, 3),
            ],
            eflags: 1 << 1,
            memory: &[(0x3800, &[0x41, 0x42, 0x43])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsw",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0x66, 0xa5],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3810),
                (I386Register::Edi, 0x3910),
                (I386Register::Ecx, 2),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x380e, &[0xaa, 0xbb, 0xcc, 0xdd])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsd",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xa5],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3820),
                (I386Register::Edi, 0x3920),
                (I386Register::Ecx, 2),
            ],
            eflags: 1 << 1,
            memory: &[(0x3820, &[0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14])],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsb",
        architecture: Architecture::I386,
        bytes: &[0xa4],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3100),
                (I386Register::Edi, 0x3200),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[(0x3100, &[0x41]), (0x3200, &[0x00])],
        }),
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsw",
        architecture: Architecture::I386,
        bytes: &[0x66, 0xa5],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3110),
                (I386Register::Edi, 0x3210),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[(0x3110, &[0x34, 0x12]), (0x3210, &[0x00, 0x00])],
        }),
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "movsd",
        architecture: Architecture::I386,
        bytes: &[0xa5],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3120),
                (I386Register::Edi, 0x3220),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[
                (0x3120, &[0x78, 0x56, 0x34, 0x12]),
                (0x3220, &[0x00, 0x00, 0x00, 0x00]),
            ],
        }),
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsb",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xa4],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3800),
                (I386Register::Edi, 0x3900),
                (I386Register::Ecx, 3),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[
                (0x3800, &[0x41, 0x42, 0x43]),
                (0x3900, &[0x00, 0x00, 0x00]),
            ],
        }),
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsw",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0x66, 0xa5],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3810),
                (I386Register::Edi, 0x3910),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: &[
                (0x380e, &[0xaa, 0xbb, 0xcc, 0xdd]),
                (0x390c, &[0x00, 0x00, 0x00, 0x00]),
            ],
        }),
    },
    X86Sample {
        mnemonic: "movs",
        instruction: "rep movsd",
        architecture: Architecture::I386,
        bytes: &[0xf3, 0xa5],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Esi, 0x3820),
                (I386Register::Edi, 0x3920),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: &[
                (0x3820, &[0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14]),
                (0x3920, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ],
        }),
    },
];

#[test]
fn movs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movs_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn movs_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
