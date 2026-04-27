use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_roundtrip_cases,
};
use crate::Architecture;

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movq",
            instruction: "movq [ebp-8], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0xd6, 0x45, 0xf8]).to_vec(),
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
                    (I386Register::Esp, 0x2fc0),
                    (
                        I386Register::Xmm0,
                        0xaabb_ccdd_eeff_0011_1122_3344_5566_7788,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2fe8, vec![0; 8])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movq",
            instruction: "movq xmm0, [ebx+4]",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x7e, 0x43, 0x04]).to_vec(),
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
                    (
                        I386Register::Xmm0,
                        0xaabb_ccdd_eeff_0011_2233_4455_6677_8899,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x3004, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movq",
            instruction: "movq [ebx+4], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0xd6, 0x43, 0x04]).to_vec(),
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
                    (I386Register::Esp, 0x2fc0),
                    (
                        I386Register::Xmm0,
                        0xaabb_ccdd_eeff_0011_2233_4455_6677_8899,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x3004, vec![0; 8])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movq",
            instruction: "movq xmm0, [esp+4]",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x7e, 0x44, 0x24, 0x04]).to_vec(),
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
                    (
                        I386Register::Xmm0,
                        0xaabb_ccdd_eeff_0011_2233_4455_6677_8899,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2ff4, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movq",
            instruction: "movq [esp+4], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0xd6, 0x44, 0x24, 0x04]).to_vec(),
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
                    (
                        I386Register::Xmm0,
                        0xaabb_ccdd_eeff_0011_2233_4455_6677_8899,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2ff4, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movq",
            instruction: "movq xmm0, [ebp-8]",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x7e, 0x45, 0xf8]).to_vec(),
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
                    (I386Register::Esp, 0x2fc0),
                    (
                        I386Register::Xmm0,
                        0xaabb_ccdd_eeff_0011_2233_4455_6677_8899,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2fe8, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            }),
        });
    }
    samples
}

#[test]
fn movq_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}
