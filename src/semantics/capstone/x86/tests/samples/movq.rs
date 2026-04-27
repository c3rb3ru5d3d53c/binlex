use super::super::support::{
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
            memory: vec![(0x2fe8, vec![0; 8])],
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
            memory: vec![(0x3004, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
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
            memory: vec![(0x3004, vec![0; 8])],
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
            memory: vec![(0x2ff4, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
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
            memory: vec![(0x2ff4, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11])],
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
            memory: vec![(0x2fe8, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
        },
    );
}
