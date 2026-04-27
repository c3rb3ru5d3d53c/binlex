use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn psrldq_semantics_stay_complete() {
    let cases = [
        ("psrldq xmm0, 1", vec![0x66, 0x0f, 0x73, 0xd8, 0x01]),
        ("vpsrldq xmm0, xmm1, 1", vec![0xc5, 0xf9, 0x73, 0xd9, 0x01]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}

#[test]
fn psrldq_semantics_match_unicorn_transitions() {
    let xmm0 = u128::from_le_bytes([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);

    assert_amd64_semantics_match_unicorn(
        "psrldq xmm0, 1",
        &[0x66, 0x0f, 0x73, 0xd8, 0x01],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, xmm0)],
            eflags: 1 << 1,
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
