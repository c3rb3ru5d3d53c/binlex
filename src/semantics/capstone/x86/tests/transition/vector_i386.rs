use super::common::{
    I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn,
};

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
