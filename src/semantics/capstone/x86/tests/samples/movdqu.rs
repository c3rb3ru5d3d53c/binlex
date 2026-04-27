use super::super::support::{
    I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn,
};

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
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x45, 0x23, 0x01,
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
            memory: vec![(0x3003, vec![0; 16])],
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
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
                    0x45, 0x23, 0x01,
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
            memory: vec![(0x2fc3, vec![0; 16])],
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
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x10,
                    0x20, 0x00, 0x00,
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
            memory: vec![(0x2fe3, vec![0; 16])],
        },
    );
}
