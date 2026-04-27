use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_roundtrip_cases,
};
use crate::Architecture;

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov eax, ebx",
            architecture: Architecture::I386,
            bytes: (&[0x89, 0xd8]).to_vec(),
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
                    (I386Register::Esp, 0x2fc0),
                ],
                eflags: 0x246,
                memory: vec![],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov rax, rbx",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0x89, 0xd8]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Rax, 0x1122_3344_5566_7788),
                    (I386Register::Rbx, 0x8877_6655_4433_2211),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Rbp, 0x2ff0),
                    (I386Register::Rsp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov eax, [ebx+4]",
            architecture: Architecture::I386,
            bytes: (&[0x8b, 0x43, 0x04]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Ebx, 0x3000),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x3004, vec![0x78, 0x56, 0x34, 0x12])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov [ebx+4], eax",
            architecture: Architecture::I386,
            bytes: (&[0x89, 0x43, 0x04]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Ebx, 0x3000),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x3004, vec![0xaa, 0xbb, 0xcc, 0xdd])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov eax, [esp+4]",
            architecture: Architecture::I386,
            bytes: (&[0x8b, 0x44, 0x24, 0x04]).to_vec(),
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
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x2ff4, vec![0x78, 0x56, 0x34, 0x12])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov [esp+4], eax",
            architecture: Architecture::I386,
            bytes: (&[0x89, 0x44, 0x24, 0x04]).to_vec(),
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
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x2ff4, vec![0xaa, 0xbb, 0xcc, 0xdd])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov eax, [ebp-4]",
            architecture: Architecture::I386,
            bytes: (&[0x8b, 0x45, 0xfc]).to_vec(),
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
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x2fec, vec![0x78, 0x56, 0x34, 0x12])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov [ebp-4], eax",
            architecture: Architecture::I386,
            bytes: (&[0x89, 0x45, 0xfc]).to_vec(),
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
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x2fec, vec![0xaa, 0xbb, 0xcc, 0xdd])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "mov",
            instruction: "mov rax, [rbx+4]",
            architecture: Architecture::AMD64,
            bytes: (&[0x48, 0x8b, 0x43, 0x04]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Rax, 0x1122_3344_5566_7788),
                    (I386Register::Rbx, 0x3000),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Rbp, 0x2ff0),
                    (I386Register::Rsp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![(0x3004, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            }),
        });
    }
    samples
}

#[test]
fn mov_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
