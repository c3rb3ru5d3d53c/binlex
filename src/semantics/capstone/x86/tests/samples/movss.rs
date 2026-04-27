use super::{X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            (
                "movss xmm0, xmm1",
                Architecture::AMD64,
                vec![0xf3, 0x0f, 0x10, 0xc1],
            ),
            (
                "movss xmm0, dword ptr [rax]",
                Architecture::AMD64,
                vec![0xf3, 0x0f, 0x10, 0x00],
            ),
        ];

        for (name, architecture, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "movss",
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
fn movss_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}
