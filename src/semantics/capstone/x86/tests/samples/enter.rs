use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "enter",
            instruction: "enter 0x10, 0x00",
            architecture: Architecture::I386,
            bytes: (&[0xc8, 0x10, 0x00, 0x00]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "enter",
            instruction: "enter 0x10, 0x01",
            architecture: Architecture::I386,
            bytes: (&[0xc8, 0x10, 0x00, 0x01]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
    }
    samples
}

fn conformance_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            (
                "enter 0x10, 0x00",
                vec![0xc8, 0x10, 0x00, 0x00],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "enter 0x10, 0x01",
                vec![0xc8, 0x10, 0x00, 0x01],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
        ];

        for (name, bytes, fixture) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "enter",
                instruction: name,
                architecture: Architecture::I386,
                bytes: (&bytes).to_vec(),
                expected_status: None,
                semantics_fixture: Some(fixture),
                roundtrip_fixture: None,
            });
        }
    }
    samples
}

#[test]
fn enter_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn enter_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
