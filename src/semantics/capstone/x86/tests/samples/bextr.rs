use super::super::support::{I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn};
use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            (
                "bextr eax, ecx, 0x21",
                vec![0x8f, 0xea, 0x78, 0x10, 0xc1, 0x21, 0x00, 0x00, 0x00],
            ),
            ("bextr eax, ecx, edx", vec![0xc4, 0xe2, 0x68, 0xf7, 0xc1]),
        ];

        for (name, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "bextr",
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

fn conformance_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "bextr",
            instruction: "bextr eax, ecx, edx",
            architecture: Architecture::AMD64,
            bytes: (&[0xc4, 0xe2, 0x68, 0xf7, 0xc1]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ecx, 0b1110_1100),
                    (I386Register::Edx, 0x0000_0201),
                ],
                eflags: 1 << 1,
                memory: vec![],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn bextr_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn bextr_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn bextr_roundtrip_amd64_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bextr eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1110_1100),
                (I386Register::Edx, 0x0000_0201),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
