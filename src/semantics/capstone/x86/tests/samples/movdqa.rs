use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn movdqa_semantics_stay_complete() {
    assert_complete_semantics(
        "vmovdqa xmm0, xmm1",
        Architecture::AMD64,
        &[0xc5, 0xf9, 0x6f, 0xc1],
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
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
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
            memory: vec![(0x3004, vec![0; 16])],
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
            memory: vec![(0x2fe0, vec![0; 16])],
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
                    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
                    0x22, 0x11, 0x00,
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
            memory: vec![(0x2fd0, vec![0; 16])],
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
                    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
                    0x22, 0x11, 0x00,
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
            memory: vec![(0x3010, vec![0; 16])],
        },
    );
}
