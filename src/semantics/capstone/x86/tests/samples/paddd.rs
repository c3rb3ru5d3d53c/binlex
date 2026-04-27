use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn paddd_semantics_stay_complete() {
    assert_complete_semantics(
        "paddd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xfe, 0xc1],
    );
}

#[test]
fn paddd_semantics_match_unicorn_transitions() {
    let xmm0 = u128::from_le_bytes([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);
    let xmm1 = u128::from_le_bytes([
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x99, 0x88,
    ]);

    assert_amd64_semantics_match_unicorn(
        "paddd xmm0, xmm1",
        &[0x66, 0x0f, 0xfe, 0xc1],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
            eflags: 1 << 1,
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
