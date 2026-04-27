use super::super::support::{I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn};
use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_roundtrip_cases,
};
use crate::Architecture;

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqu",
            instruction: "movdqu xmm0, [ebx+3]",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x6f, 0x43, 0x03]).to_vec(),
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
                        0xdead_beef_cafe_babe_0123_4567_89ab_cdef,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(
                    0x3003,
                    vec![
                        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89,
                        0x67, 0x45, 0x23, 0x01,
                    ],
                )],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqu",
            instruction: "movdqu [ebx+3], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x7f, 0x43, 0x03]).to_vec(),
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
                        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x3003, vec![0; 16])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqu",
            instruction: "movdqu xmm0, [esp+3]",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x03]).to_vec(),
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
                        0xdead_beef_cafe_babe_0123_4567_89ab_cdef,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(
                    0x2fc3,
                    vec![
                        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89,
                        0x67, 0x45, 0x23, 0x01,
                    ],
                )],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqu",
            instruction: "movdqu [esp+3], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x03]).to_vec(),
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
                        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2fc3, vec![0; 16])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqu",
            instruction: "movdqu xmm0, [ebp-13]",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x6f, 0x45, 0xf3]).to_vec(),
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
                        0xdead_beef_cafe_babe_0123_4567_89ab_cdef,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(
                    0x2fe3,
                    vec![
                        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89,
                        0x10, 0x20, 0x00, 0x00,
                    ],
                )],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqu",
            instruction: "movdqu [ebp-13], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0xf3, 0x0f, 0x7f, 0x45, 0xf3]).to_vec(),
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
                        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2fe3, vec![0; 16])],
            }),
        });
    }
    samples
}

#[test]
fn movdqu_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}

#[test]
fn movdqu_roundtrip_amd64_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqu xmm0, [rbx+3]",
        &[0xf3, 0x0f, 0x6f, 0x43, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2fc0),
                (
                    I386Register::Xmm0,
                    0xdead_beef_cafe_babe_0123_4567_89ab_cdef,
                ),
            ],
            eflags: 0x202,
            memory: vec![(
                0x3003,
                vec![
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x45, 0x23, 0x01,
                ],
            )],
        },
    );
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqu [rbx+3], xmm0",
        &[0xf3, 0x0f, 0x7f, 0x43, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![(0x3003, vec![0; 16])],
        },
    );
}

#[test]
fn movdqu_roundtrip_amd64_rsp_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqu xmm0, [rsp+3]",
        &[0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0xdead_beef_cafe_babe_0123_4567_89ab_cdef,
                ),
            ],
            eflags: 0x202,
            memory: vec![(
                0x2ff3,
                vec![
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x45, 0x23, 0x01,
                ],
            )],
        },
    );
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqu [rsp+3], xmm0",
        &[0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![(0x2ff3, vec![0; 16])],
        },
    );
}

#[test]
fn movdqu_roundtrip_amd64_rbp_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqu xmm0, [rbp-13]",
        &[0xf3, 0x0f, 0x6f, 0x45, 0xf3],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x3100),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0xdead_beef_cafe_babe_0123_4567_89ab_cdef,
                ),
            ],
            eflags: 0x202,
            memory: vec![(
                0x30f3,
                vec![
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x00, 0x00, 0x00,
                ],
            )],
        },
    );
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqu [rbp-13], xmm0",
        &[0xf3, 0x0f, 0x7f, 0x45, 0xf3],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x3100),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![(0x30f3, vec![0; 16])],
        },
    );
}
