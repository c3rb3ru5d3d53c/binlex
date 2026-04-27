use super::{X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            (
                "pextrb eax, xmm0, 1",
                vec![0x66, 0x0f, 0x3a, 0x14, 0xc0, 0x01],
            ),
            (
                "vpextrb eax, xmm0, 1",
                vec![0xc4, 0xe3, 0x79, 0x14, 0xc0, 0x01],
            ),
        ];

        for (name, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "pextrb",
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
fn pextrb_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}
