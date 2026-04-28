use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_roundtrip_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "pslldq",
        instruction: "pslldq xmm0, 1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x73, 0xf8, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pslldq",
        instruction: "vpslldq xmm0, xmm1, 1",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xf9, 0x73, 0xf9, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pslldq",
        instruction: "pslldq xmm0, 4",
        architecture: Architecture::I386,
        bytes: &[0x66, 0x0f, 0x73, 0xf8, 0x04],
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
                (I386Register::Xmm0, 0x1234_5678_89ab_cdef_0fed_cba9_7654_3210),
            ],
            eflags: 0x202,
            memory: &[],
        }),
    },
];

#[test]
fn pslldq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn pslldq_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
