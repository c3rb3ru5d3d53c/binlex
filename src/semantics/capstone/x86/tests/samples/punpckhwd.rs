use super::{X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            (
                "punpckhwd xmm0, xmm1",
                Architecture::AMD64,
                vec![0x66, 0x0f, 0x69, 0xc1],
            ),
            (
                "vpunpckhwd xmm0, xmm2, xmm1",
                Architecture::AMD64,
                vec![0xc5, 0xe9, 0x69, 0xc1],
            ),
        ];

        for (name, architecture, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "punpckhwd",
                instruction: name,
                architecture: architecture,
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
fn punpckhwd_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}
