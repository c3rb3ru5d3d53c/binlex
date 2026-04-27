use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const XMM0_CONFORMANCE: u128 = u128::from_le_bytes([
    0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
    0x22,
]);
const XMM1_CONFORMANCE: u128 = u128::from_le_bytes([
    0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
    0x88,
]);

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "paddd",
        instruction: "paddd xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0xfe, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "paddd",
        instruction: "paddd xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0xfe, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Xmm0, XMM0_CONFORMANCE),
                (I386Register::Xmm1, XMM1_CONFORMANCE),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "paddd",
        instruction: "paddd xmm0, xmm1",
        architecture: Architecture::I386,
        bytes: &[0x66, 0x0f, 0xfe, 0xc1],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (I386Register::Xmm0, 0x0011_2233_1020_3040_7fff_ff00_ffff_fffe),
                (I386Register::Xmm1, 0x0102_0304_1112_1314_0000_0100_0000_0002),
            ],
            eflags: 0x202,
            memory: &[],
        }),
    },
];

#[test]
fn paddd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn paddd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn paddd_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
