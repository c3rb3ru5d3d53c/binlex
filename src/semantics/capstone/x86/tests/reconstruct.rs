use super::common::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_i386_instruction_roundtrip_match_unicorn,
};

#[test]
fn i386_roundtrip_nop_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "nop",
        &[0x90],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_xor_eax_eax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "xor eax, eax",
        &[0x31, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Rax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movq_ptr_ebp_minus_8_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movq [ebp-8], xmm0",
        &[0x66, 0x0f, 0xd6, 0x45, 0xf8],
        I386Fixture {
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
            memory: vec![(
                0x2fe8,
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_mov_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "mov rax, rbx",
        &[0x48, 0x89, 0xd8],
        I386Fixture {
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
        },
    );
}

#[test]
fn amd64_roundtrip_add_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "add rax, rbx",
        &[0x48, 0x01, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x0102_0304_0506_0708),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_cmp_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "cmp rax, rbx",
        &[0x48, 0x39, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x0102_0304_0506_0708),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_cmovz_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "cmovz rax, rbx",
        &[0x48, 0x0f, 0x44, 0xc3],
        I386Fixture {
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
        },
    );
}

#[test]
fn amd64_roundtrip_setz_al_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "setz al",
        &[0x0f, 0x94, 0xc0],
        I386Fixture {
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
        },
    );
}

#[test]
fn amd64_roundtrip_movzx_eax_al_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movzx eax, al",
        &[0x0f, 0xb6, 0xc0],
        I386Fixture {
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
        },
    );
}

#[test]
fn amd64_roundtrip_movsx_eax_al_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "movsx eax, al",
        &[0x0f, 0xbe, 0xc0],
        I386Fixture {
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
        },
    );
}

#[test]
fn amd64_roundtrip_mov_rax_ptr_rbx_plus_4_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "mov rax, [rbx+4]",
        &[0x48, 0x8b, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(
                0x3004,
                vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqu_xmm0_ptr_rbx_plus_3_matches_unicorn() {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqu_ptr_rbx_plus_3_xmm0_matches_unicorn() {
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
            memory: vec![(
                0x3003,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqu_xmm0_ptr_rsp_plus_3_matches_unicorn() {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqu_ptr_rsp_plus_3_xmm0_matches_unicorn() {
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
            memory: vec![(
                0x2ff3,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqu_xmm0_ptr_rbp_minus_13_matches_unicorn() {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqu_ptr_rbp_minus_13_xmm0_matches_unicorn() {
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
            memory: vec![(
                0x30f3,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqa_xmm0_ptr_rbx_plus_16_matches_unicorn() {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqa_ptr_rbx_plus_16_xmm0_matches_unicorn() {
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
            memory: vec![(
                0x3010,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqa_xmm0_ptr_rsp_plus_16_matches_unicorn() {
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
            memory: vec![(
                0x3000,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            ), (
                0x2ff0 + 16,
                vec![
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqa_ptr_rsp_plus_16_xmm0_matches_unicorn() {
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
            memory: vec![(
                0x3000,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            ), (
                0x2ff0 + 16,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqa_xmm0_ptr_rbp_minus_16_matches_unicorn() {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_movdqa_ptr_rbp_minus_16_xmm0_matches_unicorn() {
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
            memory: vec![(
                0x30f0,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn amd64_roundtrip_pxor_xmm0_xmm1_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm1",
        &[0x66, 0x0f, 0xef, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_por_xmm0_xmm1_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "por xmm0, xmm1",
        &[0x66, 0x0f, 0xeb, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, ebx",
        &[0x89, 0xd8],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_bsf_ecx_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bsf ecx, eax",
        &[0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1000_0040),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_bsr_ecx_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bsr ecx, eax",
        &[0x0f, 0xbd, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1000_0040),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_bsf_ecx_eax_zero_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bsf ecx, eax",
        &[0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_bsr_ecx_eax_zero_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bsr ecx, eax",
        &[0x0f, 0xbd, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_bswap_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bswap eax",
        &[0x0f, 0xc8],
        I386Fixture {
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
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_rol_eax_1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rol eax, 1",
        &[0xd1, 0xc0],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_ror_eax_1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "ror eax, 1",
        &[0xd1, 0xc8],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_rol_eax_cl_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rol eax, cl",
        &[0xd3, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x8123_4567),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x0000_0003),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_ror_eax_cl_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "ror eax, cl",
        &[0xd3, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x8123_4567),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x0000_0003),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_rcl_eax_1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rcl eax, 1",
        &[0xd1, 0xd0],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_rcr_eax_1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rcr eax, 1",
        &[0xd1, 0xd8],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_shld_eax_edx_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "shld eax, edx, 4",
        &[0x0f, 0xa4, 0xd0, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_shrd_eax_edx_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "shrd eax, edx, 4",
        &[0x0f, 0xac, 0xd0, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_shld_eax_edx_cl_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "shld eax, edx, cl",
        &[0x0f, 0xa5, 0xd0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ecx, 0x0000_0004),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_shrd_eax_edx_cl_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "shrd eax, edx, cl",
        &[0x0f, 0xad, 0xd0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ecx, 0x0000_0004),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_bt_eax_3_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bt eax, 3",
        &[0x0f, 0xba, 0xe0, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0008),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_btc_eax_3_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "btc eax, 3",
        &[0x0f, 0xba, 0xf8, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0008),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_bts_eax_3_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bts eax, 3",
        &[0x0f, 0xba, 0xe8, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0000),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_btr_eax_3_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "btr eax, 3",
        &[0x0f, 0xba, 0xf0, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0008),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bsf_rcx_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bsf rcx, rax",
        &[0x48, 0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1000_0000_0000_0040),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_imul_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "imul eax, ebx",
        &[0x0f, 0xaf, 0xc3],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_fff0),
                (I386Register::Ebx, 5),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_imul_ecx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "imul ecx",
        &[0xf7, 0xe9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_fff0),
                (I386Register::Ecx, 5),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_xchg_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xchg eax, ebx",
        &[0x93],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_xadd_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xadd eax, ebx",
        &[0x0f, 0xc1, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x7fff_ffff),
                (I386Register::Ebx, 0x0000_0001),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmpxchg_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpxchg eax, ebx",
        &[0x0f, 0xb1, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Ebx, 0x9abc_def0),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsb",
        &[0xa4],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3100),
                (I386Register::Edi, 0x3200),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3100, vec![0x41]), (0x3200, vec![0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_movsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsd",
        &[0xa5],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsw",
        &[0x66, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3110),
                (I386Register::Edi, 0x3210),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3110, vec![0x34, 0x12]),
                (0x3210, vec![0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsb",
        &[0xf3, 0xa4],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsw",
        &[0xf3, 0x66, 0xa5],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsd",
        &[0xf3, 0xa5],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_stosb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosb",
        &[0xaa],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_00ab),
                (I386Register::Edi, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3000, vec![0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_stosw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosw",
        &[0x66, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_cdef),
                (I386Register::Edi, 0x3010),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3010, vec![0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_rep_stosw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep stosw",
        &[0xf3, 0x66, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_abcd),
                (I386Register::Edi, 0x3710),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x370c, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_stosd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosd",
        &[0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3020),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3020, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_rep_stosd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep stosd",
        &[0xf3, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edi, 0x3700),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3700, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsw",
        &[0x66, 0xad],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3310),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3310, vec![0xef, 0xbe])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsb",
        &[0xac],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3300),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3300, vec![0xaa])],
        },
    );
}

#[test]
fn i386_roundtrip_scasw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasw",
        &[0x66, 0xaf],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_1234),
                (I386Register::Edi, 0x3410),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3410, vec![0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsd",
        &[0xad],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0000),
                (I386Register::Esi, 0x3320),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
        },
    );
}

#[test]
fn i386_roundtrip_scasd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasd",
        &[0xaf],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3420),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_scasb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasb",
        &[0xae],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0041),
                (I386Register::Edi, 0x3400),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3400, vec![0x41])],
        },
    );
}

#[test]
fn i386_roundtrip_xchg_ptr_ebx_plus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xchg dword ptr [ebx+4], eax",
        &[0x87, 0x43, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: vec![(0x3004, vec![0x88, 0x77, 0x66, 0x55])],
        },
    );
}

#[test]
fn i386_roundtrip_xadd_ptr_ebx_plus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xadd dword ptr [ebx+4], eax",
        &[0x0f, 0xc1, 0x43, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x7fff_ffff),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3004, vec![0x01, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_div_ecx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "div ecx",
        &[0xf7, 0xf1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 100),
                (I386Register::Ecx, 5),
                (I386Register::Edx, 0),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_idiv_ecx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "idiv ecx",
        &[0xf7, 0xf9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_ff9c),
                (I386Register::Ecx, 5),
                (I386Register::Edx, 0xffff_ffff),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_blsi_eax_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "blsi eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xd9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1011000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_blsmsk_eax_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "blsmsk eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xd1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1011000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_blsr_eax_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "blsr eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xc9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1011000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bextr_eax_ecx_edx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bextr eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1110_1100),
                (I386Register::Edx, 0x0000_0201),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bzhi_eax_ecx_edx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bzhi eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0xffff_ffff),
                (I386Register::Edx, 5),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pdep_eax_ebx_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pdep eax, ebx, ecx",
        &[0xc4, 0xe2, 0x63, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ebx, 0b1011),
                (I386Register::Ecx, 0b0011_0101),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pext_eax_ebx_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pext eax, ebx, ecx",
        &[0xc4, 0xe2, 0x62, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ebx, 0b1011),
                (I386Register::Ecx, 0b0011_0101),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pdep_rax_rbx_rcx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pdep rax, rbx, rcx",
        &[0xc4, 0xe2, 0xe3, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0),
                (I386Register::Rbx, 0x0000_0000_0000_000b),
                (I386Register::Rcx, 0x8000_0000_0000_0035),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pext_rax_rbx_rcx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pext rax, rbx, rcx",
        &[0xc4, 0xe2, 0xe2, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0),
                (I386Register::Rbx, 0x8000_0000_0000_000b),
                (I386Register::Rcx, 0x8000_0000_0000_0035),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bsr_rcx_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bsr rcx, rax",
        &[0x48, 0x0f, 0xbd, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1000_0000_0000_0040),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bswap_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bswap rax",
        &[0x48, 0x0f, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_add_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "add eax, ebx",
        &[0x01, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_adc_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "adc eax, ebx",
        &[0x11, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x203,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_sub_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "sub eax, ebx",
        &[0x29, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_sbb_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "sbb eax, ebx",
        &[0x19, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x203,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmp_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmp eax, ebx",
        &[0x39, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_test_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "test eax, ebx",
        &[0x85, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, [ebx+4]",
        &[0x8b, 0x43, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_cmpsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsb",
        &[0xa6],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3500),
                (I386Register::Edi, 0x3600),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsw",
        &[0x66, 0xa7],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3510),
                (I386Register::Edi, 0x3610),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsd",
        &[0xa7],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_setz_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setz al",
        &[0x0f, 0x94, 0xc0],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setnz_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setnz al",
        &[0x0f, 0x95, 0xc0],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setc_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setc al",
        &[0x0f, 0x92, 0xc0],
        I386Fixture {
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
            eflags: 0x203,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_seto_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "seto al",
        &[0x0f, 0x90, 0xc0],
        I386Fixture {
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
            eflags: 0xa02,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_sets_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "sets al",
        &[0x0f, 0x98, 0xc0],
        I386Fixture {
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
            eflags: 0x282,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setbe_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setbe al",
        &[0x0f, 0x96, 0xc0],
        I386Fixture {
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
            eflags: 0x243,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmovc_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovc eax, ebx",
        &[0x0f, 0x42, 0xc3],
        I386Fixture {
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
            eflags: 0x203,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmovbe_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovbe eax, ebx",
        &[0x0f, 0x46, 0xc3],
        I386Fixture {
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
            eflags: 0x243,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setl_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setl al",
        &[0x0f, 0x9c, 0xc0],
        I386Fixture {
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
            eflags: 0x882,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmovl_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovl eax, ebx",
        &[0x0f, 0x4c, 0xc3],
        I386Fixture {
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
            eflags: 0x282,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setle_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setle al",
        &[0x0f, 0x9e, 0xc0],
        I386Fixture {
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
            eflags: 0x242,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmovle_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovle eax, ebx",
        &[0x0f, 0x4e, 0xc3],
        I386Fixture {
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
            eflags: 0x242,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setge_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setge al",
        &[0x0f, 0x9d, 0xc0],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_setg_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setg al",
        &[0x0f, 0x9f, 0xc0],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmovge_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovge eax, ebx",
        &[0x0f, 0x4d, 0xc3],
        I386Fixture {
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movzx_eax_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movzx eax, al",
        &[0x0f, 0xb6, 0xc0],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, al",
        &[0x0f, 0xbe, 0xc0],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, byte ptr [ebx+4]",
        &[0x0f, 0xbe, 0x43, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movzx_eax_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movzx eax, byte ptr [ebx+4]",
        &[0x0f, 0xb6, 0x43, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movzx_eax_word_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movzx eax, word ptr [ebx+4]",
        &[0x0f, 0xb7, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(0x3004, vec![0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_word_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, word ptr [ebx+4]",
        &[0x0f, 0xbf, 0x43, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_lea_eax_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lea eax, [ebx+4]",
        &[0x8d, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_lea_eax_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lea eax, [ebp-4]",
        &[0x8d, 0x45, 0xfc],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_lea_eax_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lea eax, [esp+4]",
        &[0x8d, 0x44, 0x24, 0x04],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_inc_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "inc eax",
        &[0x40],
        I386Fixture {
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
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_dec_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "dec eax",
        &[0x48],
        I386Fixture {
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
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_neg_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "neg eax",
        &[0xf7, 0xd8],
        I386Fixture {
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
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_not_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "not eax",
        &[0xf7, 0xd0],
        I386Fixture {
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
            eflags: 0x247,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_ptr_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, byte ptr [esp+4]",
        &[0x0f, 0xbe, 0x44, 0x24, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movzx_eax_ptr_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movzx eax, byte ptr [esp+4]",
        &[0x0f, 0xb6, 0x44, 0x24, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movzx_eax_ptr_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movzx eax, byte ptr [ebp-4]",
        &[0x0f, 0xb6, 0x45, 0xfc],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_ptr_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, byte ptr [ebp-4]",
        &[0x0f, 0xbe, 0x45, 0xfc],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_cmovz_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovz eax, ebx",
        &[0x0f, 0x44, 0xc3],
        I386Fixture {
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
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_mov_ptr_ebx_plus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov [ebx+4], eax",
        &[0x89, 0x43, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ptr_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, [esp+4]",
        &[0x8b, 0x44, 0x24, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_mov_ptr_esp_plus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov [esp+4], eax",
        &[0x89, 0x44, 0x24, 0x04],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ptr_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, [ebp-4]",
        &[0x8b, 0x45, 0xfc],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_mov_ptr_ebp_minus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov [ebp-4], eax",
        &[0x89, 0x45, 0xfc],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_push_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "push eax",
        &[0x50],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_pop_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pop eax",
        &[0x58],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_pushfd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pushfd",
        &[0x9c],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_popfd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "popfd",
        &[0x9d],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_ret_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "ret",
        &[0xc3],
        I386Fixture {
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
            memory: vec![(0x2fec, vec![0x00, 0x11, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_ret_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "ret 4",
        &[0xc2, 0x04, 0x00],
        I386Fixture {
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
            memory: vec![(0x2fec, vec![0x00, 0x11, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_leave_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "leave",
        &[0xc9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2fe0),
                (I386Register::Esp, 0x2fd0),
            ],
            eflags: 0x246,
            memory: vec![(0x2fe0, vec![0xf0, 0x2f, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_pxor_xmm0_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm0",
        &[0x66, 0x0f, 0xef, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (I386Register::Xmm0, 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_pxor_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm1",
        &[0x66, 0x0f, 0xef, 0xc1],
        I386Fixture {
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
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_por_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "por xmm0, xmm1",
        &[0x66, 0x0f, 0xeb, 0xc1],
        I386Fixture {
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
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_pand_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pand xmm0, xmm1",
        &[0x66, 0x0f, 0xdb, 0xc1],
        I386Fixture {
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
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_paddd_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "paddd xmm0, xmm1",
        &[0x66, 0x0f, 0xfe, 0xc1],
        I386Fixture {
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
                    0x0011_2233_1020_3040_7fff_ff00_ffff_fffe,
                ),
                (
                    I386Register::Xmm1,
                    0x0102_0304_1112_1314_0000_0100_0000_0002,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_psubd_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "psubd xmm0, xmm1",
        &[0x66, 0x0f, 0xfa, 0xc1],
        I386Fixture {
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
                    0x0102_0304_2223_2425_8000_0001_0000_0005,
                ),
                (
                    I386Register::Xmm1,
                    0x0001_0002_1112_1314_0000_0001_0000_0003,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_pslld_xmm0_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pslld xmm0, 4",
        &[0x66, 0x0f, 0x72, 0xf0, 0x04],
        I386Fixture {
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
                    0x1234_5678_89ab_cdef_0fed_cba9_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_psrld_xmm0_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "psrld xmm0, 4",
        &[0x66, 0x0f, 0x72, 0xd0, 0x04],
        I386Fixture {
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
                    0x1234_5678_89ab_cdef_0fed_cba9_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_psrad_xmm0_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "psrad xmm0, 4",
        &[0x66, 0x0f, 0x72, 0xe0, 0x04],
        I386Fixture {
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
                    0xf234_5678_89ab_cdef_8fed_cba9_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_pslldq_xmm0_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pslldq xmm0, 4",
        &[0x66, 0x0f, 0x73, 0xf8, 0x04],
        I386Fixture {
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
                    0x1234_5678_89ab_cdef_0fed_cba9_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_psrldq_xmm0_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "psrldq xmm0, 4",
        &[0x66, 0x0f, 0x73, 0xd8, 0x04],
        I386Fixture {
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
                    0x1234_5678_89ab_cdef_0fed_cba9_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_punpcklbw_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "punpcklbw xmm0, xmm1",
        &[0x66, 0x0f, 0x60, 0xc1],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, xmm1",
        &[0x66, 0x0f, 0x6f, 0xc1],
        I386Fixture {
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
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_xmm0_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, [ebx+4]",
        &[0x66, 0x0f, 0x6f, 0x43, 0x04],
        I386Fixture {
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
                    0x00, 0x11, 0x22, 0x33,
                    0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb,
                    0xcc, 0xdd, 0xee, 0xff,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_ptr_ebx_plus_4_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa [ebx+4], xmm0",
        &[0x66, 0x0f, 0x7f, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(
                0x3004,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_ptr_ebp_minus_16_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa [ebp-16], xmm0",
        &[0x66, 0x0f, 0x7f, 0x45, 0xf0],
        I386Fixture {
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
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_xmm0_ptr_ebp_minus_16_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, [ebp-16]",
        &[0x66, 0x0f, 0x6f, 0x45, 0xf0],
        I386Fixture {
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
                    0xff, 0xee, 0xdd, 0xcc,
                    0xbb, 0xaa, 0x99, 0x88,
                    0x77, 0x66, 0x55, 0x44,
                    0x33, 0x22, 0x11, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_ptr_esp_plus_16_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa [esp+16], xmm0",
        &[0x66, 0x0f, 0x7f, 0x44, 0x24, 0x10],
        I386Fixture {
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
            memory: vec![(
                0x2fd0,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_xmm0_ptr_esp_plus_16_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa xmm0, [esp+16]",
        &[0x66, 0x0f, 0x6f, 0x44, 0x24, 0x10],
        I386Fixture {
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
                    0xff, 0xee, 0xdd, 0xcc,
                    0xbb, 0xaa, 0x99, 0x88,
                    0x77, 0x66, 0x55, 0x44,
                    0x33, 0x22, 0x11, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqa_ptr_ebx_plus_16_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqa [ebx+16], xmm0",
        &[0x66, 0x0f, 0x7f, 0x43, 0x10],
        I386Fixture {
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
            memory: vec![(
                0x3010,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqu_xmm0_ptr_ebx_plus_3_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqu xmm0, [ebx+3]",
        &[0xf3, 0x0f, 0x6f, 0x43, 0x03],
        I386Fixture {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqu_ptr_ebx_plus_3_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqu [ebx+3], xmm0",
        &[0xf3, 0x0f, 0x7f, 0x43, 0x03],
        I386Fixture {
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
            memory: vec![(
                0x3003,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqu_xmm0_ptr_esp_plus_3_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqu xmm0, [esp+3]",
        &[0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x03],
        I386Fixture {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x67, 0x45, 0x23, 0x01,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqu_ptr_esp_plus_3_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqu [esp+3], xmm0",
        &[0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x03],
        I386Fixture {
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
            memory: vec![(
                0x2fc3,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqu_xmm0_ptr_ebp_minus_13_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqu xmm0, [ebp-13]",
        &[0xf3, 0x0f, 0x6f, 0x45, 0xf3],
        I386Fixture {
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
                    0x10, 0x32, 0x54, 0x76,
                    0x98, 0xba, 0xdc, 0xfe,
                    0xef, 0xcd, 0xab, 0x89,
                    0x10, 0x20, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movdqu_ptr_ebp_minus_13_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movdqu [ebp-13], xmm0",
        &[0xf3, 0x0f, 0x7f, 0x45, 0xf3],
        I386Fixture {
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
            memory: vec![(
                0x2fe3,
                vec![
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movd_eax_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movd eax, xmm0",
        &[0x66, 0x0f, 0x7e, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (I386Register::Xmm0, 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movd_xmm0_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movd xmm0, eax",
        &[0x66, 0x0f, 0x6e, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (I386Register::Xmm0, 0xaabb_ccdd_eeff_0011_2233_4455_6677_8899),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_movd_xmm0_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movd xmm0, [ebx+4]",
        &[0x66, 0x0f, 0x6e, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(0x3004, vec![0x44, 0x33, 0x22, 0x11])],
        },
    );
}

#[test]
fn i386_roundtrip_movd_ptr_ebx_plus_4_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movd [ebx+4], xmm0",
        &[0x66, 0x0f, 0x7e, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(0x3004, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_movq_xmm0_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movq xmm0, [ebx+4]",
        &[0xf3, 0x0f, 0x7e, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(
                0x3004,
                vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movq_ptr_ebx_plus_4_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movq [ebx+4], xmm0",
        &[0x66, 0x0f, 0xd6, 0x43, 0x04],
        I386Fixture {
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
            memory: vec![(
                0x3004,
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movq_xmm0_ptr_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movq xmm0, [esp+4]",
        &[0xf3, 0x0f, 0x7e, 0x44, 0x24, 0x04],
        I386Fixture {
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
            memory: vec![(
                0x2ff4,
                vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movq_ptr_esp_plus_4_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movq [esp+4], xmm0",
        &[0x66, 0x0f, 0xd6, 0x44, 0x24, 0x04],
        I386Fixture {
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
            memory: vec![(
                0x2ff4,
                vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movq_xmm0_ptr_ebp_minus_8_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movq xmm0, [ebp-8]",
        &[0xf3, 0x0f, 0x7e, 0x45, 0xf8],
        I386Fixture {
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
            memory: vec![(
                0x2fe8,
                vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            )],
        },
    );
}

#[test]
fn i386_roundtrip_movd_xmm0_ptr_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movd xmm0, [ebp-4]",
        &[0x66, 0x0f, 0x6e, 0x45, 0xfc],
        I386Fixture {
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
            memory: vec![(0x2fec, vec![0x44, 0x33, 0x22, 0x11])],
        },
    );
}

#[test]
fn i386_roundtrip_movd_ptr_ebp_minus_4_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movd [ebp-4], xmm0",
        &[0x66, 0x0f, 0x7e, 0x45, 0xfc],
        I386Fixture {
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
            memory: vec![(0x2fec, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}
