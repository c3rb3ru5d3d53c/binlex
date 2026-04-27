use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_roundtrip_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            ("rcl eax, 1", Architecture::I386, vec![0xd1, 0xd0]),
            ("rcl rax, 1", Architecture::AMD64, vec![0x48, 0xd1, 0xd0]),
        ];

        for (name, architecture, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "rcl",
                instruction: name,
                architecture: architecture,
                bytes: (&bytes).to_vec(),
                expected_status: Some(SemanticStatus::Complete),
                semantics_fixture: None,
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
            mnemonic: "rcl",
            instruction: "rcl eax, 1",
            architecture: Architecture::I386,
            bytes: (&[0xd1, 0xd0]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x8123_4567),
                    (I386Register::Ebx, 0x5566_7788),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x203,
                memory: vec![],
            }),
        });
    }
    samples
}

#[test]
fn rcl_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn rcl_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
