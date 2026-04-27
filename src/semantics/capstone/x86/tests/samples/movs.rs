use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_roundtrip_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "movsb",
            architecture: Architecture::I386,
            bytes: (&[0xa4]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "movsw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xa5]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "movsd",
            architecture: Architecture::I386,
            bytes: (&[0xa5]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "movsq",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0xa5]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsb",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0xa4]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsw",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x66, 0xa5]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsd",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0xa5]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsq",
            architecture: Architecture::AMD64,
            bytes: (&[0xf3, 0x48, 0xa5]).to_vec(),
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
                "movsb",
                vec![0xa4],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esi, 0x3100), (I386Register::Edi, 0x3200)],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![(0x3100, vec![0x41])],
                },
            ),
            (
                "movsw",
                vec![0x66, 0xa5],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esi, 0x3110), (I386Register::Edi, 0x3210)],
                    eflags: 1 << 1,
                    memory: vec![(0x3110, vec![0x34, 0x12])],
                },
            ),
            (
                "movsd",
                vec![0xa5],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Esi, 0x3120), (I386Register::Edi, 0x3220)],
                    eflags: 1 << 1,
                    memory: vec![(0x3120, vec![0x78, 0x56, 0x34, 0x12])],
                },
            ),
            (
                "rep movsb",
                vec![0xf3, 0xa4],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Esi, 0x3800),
                        (I386Register::Edi, 0x3900),
                        (I386Register::Ecx, 3),
                    ],
                    eflags: 1 << 1,
                    memory: vec![(0x3800, vec![0x41, 0x42, 0x43])],
                },
            ),
            (
                "rep movsw",
                vec![0xf3, 0x66, 0xa5],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Esi, 0x3810),
                        (I386Register::Edi, 0x3910),
                        (I386Register::Ecx, 2),
                    ],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![(0x380e, vec![0xaa, 0xbb, 0xcc, 0xdd])],
                },
            ),
            (
                "rep movsd",
                vec![0xf3, 0xa5],
                X86RuntimeFixtureSpec {
                    registers: vec![
                        (I386Register::Esi, 0x3820),
                        (I386Register::Edi, 0x3920),
                        (I386Register::Ecx, 2),
                    ],
                    eflags: 1 << 1,
                    memory: vec![(0x3820, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14])],
                },
            ),
        ];

        for (name, bytes, fixture) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "movs",
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
            mnemonic: "movs",
            instruction: "movsb",
            architecture: Architecture::I386,
            bytes: (&[0xa4]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3100),
                    (I386Register::Edi, 0x3200),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3100, vec![0x41]), (0x3200, vec![0x00])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "movsw",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0xa5]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3110),
                    (I386Register::Edi, 0x3210),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3110, vec![0x34, 0x12]), (0x3210, vec![0x00, 0x00])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "movsd",
            architecture: Architecture::I386,
            bytes: (&[0xa5]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3120),
                    (I386Register::Edi, 0x3220),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![
                    (0x3120, vec![0x78, 0x56, 0x34, 0x12]),
                    (0x3220, vec![0x00, 0x00, 0x00, 0x00]),
                ],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsb",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0xa4]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3800),
                    (I386Register::Edi, 0x3900),
                    (I386Register::Ecx, 3),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![
                    (0x3800, vec![0x41, 0x42, 0x43]),
                    (0x3900, vec![0x00, 0x00, 0x00]),
                ],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsw",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x66, 0xa5]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3810),
                    (I386Register::Edi, 0x3910),
                    (I386Register::Ecx, 2),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![
                    (0x380e, vec![0xaa, 0xbb, 0xcc, 0xdd]),
                    (0x390c, vec![0x00, 0x00, 0x00, 0x00]),
                ],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movs",
            instruction: "rep movsd",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0xa5]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Esi, 0x3820),
                    (I386Register::Edi, 0x3920),
                    (I386Register::Ecx, 2),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 1 << 1,
                memory: vec![
                    (0x3820, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14]),
                    (0x3920, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                ],
            }),
        });
    }
    samples
}

#[test]
fn movs_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn movs_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn movs_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
