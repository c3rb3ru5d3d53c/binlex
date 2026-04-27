use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const XMM0: u128 = u128::from_le_bytes([
    0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
    0x22,
]);

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "movntdq",
        instruction: "movntdq xmmword ptr [rax], xmm0",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0xe7, 0x00],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movntdq",
        instruction: "vmovntdq xmmword ptr [rax], xmm0",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xf9, 0xe7, 0x00],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movntdq",
        instruction: "movntdq xmmword ptr [rax], xmm0",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0xe7, 0x00],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Rax, 0x3000), (I386Register::Xmm0, XMM0)],
            eflags: 1 << 1,
            memory: &[(0x3000, &[0; 16])],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn movntdq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movntdq_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
