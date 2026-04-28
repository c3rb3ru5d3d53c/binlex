use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldnp",
        instruction: "ldnp	x0, x1, [x2]",
        bytes: &[0x40, 0x04, 0x40, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldnp",
        instruction: "ldnp	x0, x1, [x2]",
        bytes: &[0x40, 0x04, 0x40, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(
                0x3000,
                &[
                    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc,
                    0xbb, 0xaa, 0x99,
                ],
            )],
        }),
    },
];

#[test]
fn ldnp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldnp_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
