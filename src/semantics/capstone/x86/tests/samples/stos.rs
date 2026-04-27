use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_roundtrip_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "stosb",
            architecture: Architecture::I386,
            bytes: (&[0xaa]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "stosw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xab]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "stosd",
            architecture: Architecture::I386,
            bytes: (&[0xab]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "stosq",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0xab]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "rep stosd",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0xab]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "rep stosw",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x66, 0xab]).to_vec(),
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
                "stosb",
                vec![0xaa],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x0000_00ab),
                        (I386Register::Edi, 0x3000),
                    ],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![],
                },
            ),
            (
                "stosw",
                vec![0x66, 0xab],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x0000_cdef),
                        (I386Register::Edi, 0x3010),
                    ],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "stosd",
                vec![0xab],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x1234_5678),
                        (I386Register::Edi, 0x3020),
                    ],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "rep stosd",
                vec![0xf3, 0xab],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x1122_3344),
                        (I386Register::Edi, 0x3700),
                        (I386Register::Ecx, 2),
                    ],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "rep stosw",
                vec![0xf3, 0x66, 0xab],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0x0000_abcd),
                        (I386Register::Edi, 0x3710),
                        (I386Register::Ecx, 2),
                    ],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![],
                },
            ),
        ];

        for (name, bytes, fixture) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "stos",
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
            mnemonic: "stos",
            instruction: "stosb",
            architecture: Architecture::I386,
            bytes: (&[0xaa]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x0000_00ab),
                    (I386Register::Edi, 0x3000),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3000, vec![0x00])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "stosw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xab]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x0000_cdef),
                    (I386Register::Edi, 0x3010),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3010, vec![0x00, 0x00])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "stosd",
            architecture: Architecture::I386,
            bytes: (&[0xab]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Edi, 0x3020),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3020, vec![0x00, 0x00, 0x00, 0x00])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "rep stosw",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x66, 0xab]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x0000_abcd),
                    (I386Register::Edi, 0x3710),
                    (I386Register::Ecx, 2),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x370c, vec![0x00, 0x00, 0x00, 0x00])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "stos",
            instruction: "rep stosd",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0xab]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Edi, 0x3700),
                    (I386Register::Ecx, 2),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3700, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
            }),
        });
    }
    samples
}

#[test]
fn stos_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn stos_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn stos_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
