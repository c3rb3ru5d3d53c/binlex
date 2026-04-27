use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_roundtrip_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "popal",
            architecture: Architecture::I386,
            bytes: (&[0x61]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "popfd",
            architecture: Architecture::I386,
            bytes: (&[0x9d]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "popfq",
            architecture: Architecture::AMD64,
            bytes: (&[0x9d]).to_vec(),
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
        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "pop eax",
            architecture: Architecture::I386,
            bytes: (&[0x58]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esp, 0x2800),
                ],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x78, 0x56, 0x34, 0x12])],
            }),
            roundtrip_fixture: None,
        });

        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "popal",
            architecture: Architecture::I386,
            bytes: (&[0x61]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ecx, 0),
                    (I386Register::Edx, 0),
                    (I386Register::Ebx, 0),
                    (I386Register::Esp, 0x2800),
                    (I386Register::Ebp, 0),
                    (I386Register::Esi, 0),
                    (I386Register::Edi, 0),
                ],
                eflags: 1 << 1,
                memory: vec![(
                    0x2800,
                    vec![
                        0x77, 0x77, 0x77, 0x77, 0x66, 0x66, 0x66, 0x66, 0x55, 0x55, 0x55, 0x55,
                        0x40, 0x28, 0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x33, 0x33, 0x33, 0x33,
                        0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11,
                    ],
                )],
            }),
            roundtrip_fixture: None,
        });

        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "popfd",
            architecture: Architecture::I386,
            bytes: (&[0x9d]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Esp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x35, 0x06, 0x00, 0x00])],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "pop eax",
            architecture: Architecture::I386,
            bytes: (&[0x58]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Ebx, 0x5566_7788),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fec),
                ],
                eflags: 0x246,
                memory: vec![(0x2fec, vec![0x78, 0x56, 0x34, 0x12])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "pop",
            instruction: "popfd",
            architecture: Architecture::I386,
            bytes: (&[0x9d]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Ebx, 0x5566_7788),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2fec),
                ],
                eflags: 0x202,
                memory: vec![(0x2fec, vec![0x46, 0x02, 0x00, 0x00])],
            }),
        });
    }
    samples
}

#[test]
fn pop_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn pop_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn pop_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
