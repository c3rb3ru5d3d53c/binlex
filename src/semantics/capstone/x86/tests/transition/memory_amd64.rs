use super::common::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
};

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
