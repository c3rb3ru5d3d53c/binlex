use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_roundtrip_cases,
};
use crate::Architecture;

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movsx",
            instruction: "movsx eax, al",
            architecture: Architecture::I386,
            bytes: (&[0x0f, 0xbe, 0xc0]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Eax, 0x1122_3384),
                    (I386Register::Ebx, 0x5566_7788),
                    (I386Register::Ecx, 0x99aa_bbcc),
                    (I386Register::Edx, 0xddee_ff00),
                    (I386Register::Esi, 0x1234_5678),
                    (I386Register::Edi, 0x8765_4321),
                    (I386Register::Ebp, 0x2ff0),
                    (I386Register::Esp, 0x2ff0),
                ],
                eflags: 0x246,
                memory: vec![],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movsx",
            instruction: "movsx eax, byte ptr [ebx+4]",
            architecture: Architecture::I386,
            bytes: (&[0x0f, 0xbe, 0x43, 0x04]).to_vec(),
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
                memory: vec![(0x3004, vec![0x84])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movsx",
            instruction: "movsx eax, word ptr [ebx+4]",
            architecture: Architecture::I386,
            bytes: (&[0x0f, 0xbf, 0x43, 0x04]).to_vec(),
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
                memory: vec![(0x3004, vec![0x34, 0xf2])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movsx",
            instruction: "movsx eax, byte ptr [esp+4]",
            architecture: Architecture::I386,
            bytes: (&[0x0f, 0xbe, 0x44, 0x24, 0x04]).to_vec(),
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
                memory: vec![(0x2ff4, vec![0x84])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movsx",
            instruction: "movsx eax, byte ptr [ebp-4]",
            architecture: Architecture::I386,
            bytes: (&[0x0f, 0xbe, 0x45, 0xfc]).to_vec(),
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
                memory: vec![(0x2fec, vec![0x84])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movsx",
            instruction: "movsx eax, al",
            architecture: Architecture::AMD64,
            bytes: (&[0x0f, 0xbe, 0xc0]).to_vec(),
            expected_status: None,
            semantics_fixture: None,
            roundtrip_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Rax, 0x1122_3344_5566_7784),
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
    samples
}

#[test]
fn movsx_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
