use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldurb",
        instruction: "ldurb	w0, [x1, #8]",
        bytes: &[0x20, 0x80, 0x40, 0x38],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldurb",
        instruction: "ldurb	w0, [x1, #8]",
        bytes: &[0x20, 0x80, 0x40, 0x38],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000)],
            memory: &[(0x3008, &[0xab])],
        }),
    },
];

#[test]
fn ldurb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldurb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
