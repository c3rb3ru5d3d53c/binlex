use super::{X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

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
