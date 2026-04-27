use super::{I386Fixture, I386Register, X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

use super::super::support::{WideI386Fixture, interpret_amd64_wide_semantics};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            (
                "pshufd xmm0, xmm1, 0x1b",
                vec![0x66, 0x0f, 0x70, 0xc1, 0x1b],
            ),
            (
                "vpshufd xmm0, xmm1, 0x1b",
                vec![0xc5, 0xf9, 0x70, 0xc1, 0x1b],
            ),
        ];

        for (name, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "pshufd",
                instruction: name,
                architecture: Architecture::AMD64,
                bytes: (&bytes).to_vec(),
                expected_status: Some(SemanticStatus::Complete),
                semantics_fixture: None,
                roundtrip_fixture: None,
            });
        }
    }
    samples
}

#[test]
fn pshufd_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn vpshufd_semantics_wide_regression_stays_stable() {
    let ymm1 = vec![
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
        0x88, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69,
        0x87, 0x78,
    ];

    let (registers, _) = interpret_amd64_wide_semantics(
        "vpshufd ymm0, ymm1, 0x1b",
        &[0xc5, 0xfd, 0x70, 0xc1, 0x1b],
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
            0x11, 0x00, 0x99, 0x88, 0x55, 0x44, 0x33, 0x22, 0x03, 0xfd, 0x04, 0xfc, 0x01, 0xff,
            0x02, 0xfe, 0x96, 0x69, 0x87, 0x78, 0xb4, 0x4b, 0xa5, 0x5a, 0xd2, 0x2d, 0xc3, 0x3c,
            0xf0, 0x0f, 0xe1, 0x1e,
        ])
    );
}
