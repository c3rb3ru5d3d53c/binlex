use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_roundtrip_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "lods",
            instruction: "lodsb",
            architecture: Architecture::I386,
            bytes: (&[0xac]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "lods",
            instruction: "lodsw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xad]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "lods",
            instruction: "lodsd",
            architecture: Architecture::I386,
            bytes: (&[0xad]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "lods",
            instruction: "lodsq",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0xad]).to_vec(),
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
                "lodsb",
                vec![0xac],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0xdead_beef),
                        (I386Register::Esi, 0x3300),
                    ],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![(0x3300, vec![0xaa])],
                },
            ),
            (
                "lodsw",
                vec![0x66, 0xad],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Eax, 0xdead_beef),
                        (I386Register::Esi, 0x3310),
                    ],
                    eflags: 1 << 1,
                    memory: vec![(0x3310, vec![0xef, 0xbe])],
                },
            ),
            (
                "lodsd",
                vec![0xad],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0), (I386Register::Esi, 0x3320)],
                    eflags: 1 << 1,
                    memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
                },
            ),
        ];

        for (name, bytes, fixture) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "lods",
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
            mnemonic: "lods",
            instruction: "lodsb",
            architecture: Architecture::I386,
            bytes: (&[0xac]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esi, 0x3300),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3300, vec![0xaa])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "lods",
            instruction: "lodsw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xad]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esi, 0x3310),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3310, vec![0xef, 0xbe])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "lods",
            instruction: "lodsd",
            architecture: Architecture::I386,
            bytes: (&[0xad]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x0000_0000),
                    (I386Register::Esi, 0x3320),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
            }),
        });
    }
    samples
}

#[test]
fn lods_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn lods_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn lods_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
