use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "rev64",
        instruction: "rev64	v0.16b, v1.16b",
        bytes: &[0x20, 0x08, 0x20, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "rev64",
        instruction: "rev64	v0.2s, v1.2s",
        bytes: &[0x20, 0x08, 0xa0, 0x0e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "rev64",
        instruction: "rev64	v0.16b, v1.16b",
        bytes: &[0x20, 0x08, 0x20, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "rev64",
        instruction: "rev64	v0.2s, v1.2s",
        bytes: &[0x20, 0x08, 0xa0, 0x0e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x0000_0000_0000_0000_1122_3344_5566_7788u128)],
            memory: &[],
        }),
    },
];

#[test]
fn rev64_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn rev64_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
