use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_roundtrip_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "shrd",
        instruction: "shrd eax, edx, cl",
        architecture: Architecture::I386,
        bytes: &[0x0f, 0xad, 0xd0],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ecx, 0x0000_0004),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
    },
    X86Sample {
        mnemonic: "shrd",
        instruction: "shrd eax, edx, 4",
        architecture: Architecture::I386,
        bytes: &[0x0f, 0xac, 0xd0, 0x04],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
    },
];

#[test]
fn shrd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn shrd_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
