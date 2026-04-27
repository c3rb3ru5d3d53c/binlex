use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_roundtrip_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasb",
            architecture: Architecture::I386,
            bytes: (&[0xae]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xaf]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasd",
            architecture: Architecture::I386,
            bytes: (&[0xaf]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasq",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0xaf]).to_vec(),
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
                "scasb",
                vec![0xae],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x0000_0041),
                        (I386Register::Edi, 0x3400),
                    ],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![(0x3400, vec![0x41])],
                },
            ),
            (
                "scasw",
                vec![0x66, 0xaf],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x0000_1234),
                        (I386Register::Edi, 0x3410),
                    ],
                    eflags: 1 << 1,
                    memory: vec![(0x3410, vec![0x34, 0x12])],
                },
            ),
            (
                "scasd",
                vec![0xaf],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x1234_5678),
                        (I386Register::Edi, 0x3420),
                    ],
                    eflags: 1 << 1,
                    memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
                },
            ),
        ];

        for (name, bytes, fixture) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "scas",
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

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasb",
            architecture: Architecture::I386,
            bytes: (&[0xae]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x0000_0041),
                    (I386Register::Edi, 0x3400),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3400, vec![0x41])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xaf]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x0000_1234),
                    (I386Register::Edi, 0x3410),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3410, vec![0x34, 0x12])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "scas",
            instruction: "scasd",
            architecture: Architecture::I386,
            bytes: (&[0xaf]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Edi, 0x3420),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
            }),
        });
    }
    samples
}

#[test]
fn scas_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn scas_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn scas_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
