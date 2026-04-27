use super::super::support::{
    I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn,
};

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
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
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
                (
                    I386Register::Xmm0,
                    0xaabb_ccdd_eeff_0011_2233_4455_6677_8899,
                ),
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
