use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cmn",
        instruction: "cmn	x0, x1",
        bytes: &[0x1f, 0x00, 0x01, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cmn",
        instruction: "cmn	x0, x1",
        bytes: &[0x1f, 0x00, 0x01, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x0", 0x7fff_ffff_ffff_ffff),
                ("x1", 1),
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cmn",
        instruction: "cmn	w0, w1",
        bytes: &[0x1f, 0x00, 0x01, 0x2b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("w0", 0x7fff_ffff),
                ("w1", 1),
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn cmn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmn_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
