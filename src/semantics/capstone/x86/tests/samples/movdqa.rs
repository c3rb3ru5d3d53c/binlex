use super::super::support::{I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn};
use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_roundtrip_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "vmovdqa xmm0, xmm1",
            architecture: Architecture::AMD64,
            bytes: (&[0xc5, 0xf9, 0x6f, 0xc1]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
    }
    samples
}

fn roundtrip_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa xmm0, xmm1",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x6f, 0xc1]).to_vec(),
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
                        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                    ),
                    (
                        I386Register::Xmm1,
                        0xffee_ddcc_bbaa_9988_7766_5544_3322_1100,
                    ),
                ],
                eflags: 0x202,
                memory: vec![],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa xmm0, [ebx+4]",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x6f, 0x43, 0x04]).to_vec(),
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
                        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(
                    0x3004,
                    vec![
                        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                        0xcc, 0xdd, 0xee, 0xff,
                    ],
                )],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa [ebx+4], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x7f, 0x43, 0x04]).to_vec(),
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
                        0xffee_ddcc_bbaa_9988_7766_5544_3322_1100,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x3004, vec![0; 16])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa [ebp-16], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x7f, 0x45, 0xf0]).to_vec(),
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
                        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2fe0, vec![0; 16])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa xmm0, [ebp-16]",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x6f, 0x45, 0xf0]).to_vec(),
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
                        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(
                    0x2fe0,
                    vec![
                        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
                        0x33, 0x22, 0x11, 0x00,
                    ],
                )],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa [esp+16], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x7f, 0x44, 0x24, 0x10]).to_vec(),
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
                        0xffee_ddcc_bbaa_9988_7766_5544_3322_1100,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x2fd0, vec![0; 16])],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa xmm0, [esp+16]",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x6f, 0x44, 0x24, 0x10]).to_vec(),
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
                        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(
                    0x2fd0,
                    vec![
                        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
                        0x33, 0x22, 0x11, 0x00,
                    ],
                )],
            }),
        });
    }
    {
        samples.push(X86RuntimeSample {
            mnemonic: "movdqa",
            instruction: "movdqa [ebx+16], xmm0",
            architecture: Architecture::I386,
            bytes: (&[0x66, 0x0f, 0x7f, 0x43, 0x10]).to_vec(),
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
                        0xffee_ddcc_bbaa_9988_7766_5544_3322_1100,
                    ),
                ],
                eflags: 0x202,
                memory: vec![(0x3010, vec![0; 16])],
            }),
        });
    }
    samples
}

#[test]
fn movdqa_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn movdqa_roundtrip_matches_unicorn() {
    let samples = roundtrip_samples();
    assert_runtime_roundtrip_cases(&samples);
}

#[test]
fn movdqa_roundtrip_amd64_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, [rbx+16]",
        &[0x66, 0x0f, 0x6f, 0x43, 0x10],
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
                0x3010,
                vec![
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x45, 0x23, 0x01,
                ],
            )],
        },
    );
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqa [rbx+16], xmm0",
        &[0x66, 0x0f, 0x7f, 0x43, 0x10],
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
            memory: vec![(0x3010, vec![0; 16])],
        },
    );
}

#[test]
fn movdqa_roundtrip_amd64_rsp_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, [rsp+16]",
        &[0x66, 0x0f, 0x6f, 0x44, 0x24, 0x10],
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
            memory: vec![
                (0x3000, vec![0; 16]),
                (
                    0x3010,
                    vec![
                        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89,
                        0x67, 0x45, 0x23, 0x01,
                    ],
                ),
            ],
        },
    );
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqa [rsp+16], xmm0",
        &[0x66, 0x0f, 0x7f, 0x44, 0x24, 0x10],
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
            memory: vec![(0x3000, vec![0; 16]), (0x3010, vec![0; 16])],
        },
    );
}

#[test]
fn movdqa_roundtrip_amd64_rbp_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, [rbp-16]",
        &[0x66, 0x0f, 0x6f, 0x45, 0xf0],
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
                0x30f0,
                vec![
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x45, 0x23, 0x01,
                ],
            )],
        },
    );
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movdqa [rbp-16], xmm0",
        &[0x66, 0x0f, 0x7f, 0x45, 0xf0],
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
            memory: vec![(0x30f0, vec![0; 16])],
        },
    );
}
