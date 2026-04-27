use super::{X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            ("pminub xmm0, xmm1", vec![0x66, 0x0f, 0xda, 0xc1]),
            ("vpminub xmm0, xmm2, xmm1", vec![0xc5, 0xe9, 0xda, 0xc1]),
        ];

        for (name, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "pminub",
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
fn pminub_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}
