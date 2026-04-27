use super::{X86RuntimeSample, assert_runtime_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "adox",
            instruction: "adox eax, ebx",
            architecture: Architecture::AMD64,
            bytes: (&[0xf3, 0x0f, 0x38, 0xf6, 0xc3]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn adox_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}
