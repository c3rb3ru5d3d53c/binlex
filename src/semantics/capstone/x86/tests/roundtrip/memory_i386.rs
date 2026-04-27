use super::common::{I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn};

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









