use super::{I386Fixture, I386Register, X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

use super::super::support::{WideI386Fixture, interpret_amd64_wide_semantics};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpermq",
    instruction: "vpermq ymm0, ymm1, 0x1b",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpermq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn vpermq_semantics_wide_regression_stays_stable() {
    let ymm1 = vec![
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
        0x88, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69,
        0x87, 0x78,
    ];

    let (registers, _) = interpret_amd64_wide_semantics(
        "vpermq ymm0, ymm1, 0x1b",
        SAMPLES[0].bytes,
        WideI386Fixture {
            base: I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
            wide_registers: vec![
                (I386Register::Ymm0, vec![0; 32]),
                (I386Register::Ymm1, ymm1),
            ],
        },
    );

    assert_eq!(
        registers.get("ymm0"),
        Some(&vec![
            0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69, 0x87, 0x78, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d,
            0xc3, 0x3c, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x01, 0xff, 0x02, 0xfe,
            0x03, 0xfd, 0x04, 0xfc,
        ])
    );
}
