use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_roundtrip_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "cmps",
            instruction: "cmpsb",
            architecture: Architecture::I386,
            bytes: (&[0xa6]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "cmps",
            instruction: "cmpsw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xa7]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "cmps",
            instruction: "cmpsd",
            architecture: Architecture::I386,
            bytes: (&[0xa7]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "cmps",
            instruction: "cmpsq",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0xa7]).to_vec(),
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
                "cmpsb",
                vec![0xa6],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esi, 0x3500), (I386Register::Edi, 0x3600)],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
                },
            ),
            (
                "cmpsw",
                vec![0x66, 0xa7],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esi, 0x3510), (I386Register::Edi, 0x3610)],
                    eflags: 1 << 1,
                    memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
                },
            ),
            (
                "cmpsd",
                vec![0xa7],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esi, 0x3520), (I386Register::Edi, 0x3620)],
                    eflags: 1 << 1,
                    memory: vec![
                        (0x3520, vec![0x78, 0x56, 0x34, 0x12]),
                        (0x3620, vec![0x77, 0x56, 0x34, 0x12]),
                    ],
                },
            ),
        ];

        for (name, bytes, fixture) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "cmps",
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
            mnemonic: "cmps",
            instruction: "cmpsb",
            architecture: Architecture::I386,
            bytes: (&[0xa6]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3500),
                    (I386Register::Edi, 0x3600),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "cmps",
            instruction: "cmpsw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xa7]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3510),
                    (I386Register::Edi, 0x3610),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "cmps",
            instruction: "cmpsd",
            architecture: Architecture::I386,
            bytes: (&[0xa7]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3520),
                    (I386Register::Edi, 0x3620),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![
                    (0x3520, vec![0x78, 0x56, 0x34, 0x12]),
                    (0x3620, vec![0x77, 0x56, 0x34, 0x12]),
                ],
            }),
        });
    }
    samples
}

#[test]
fn cmps_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn cmps_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn cmps_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
