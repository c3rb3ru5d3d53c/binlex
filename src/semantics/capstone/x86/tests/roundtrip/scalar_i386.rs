use super::common::{I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn};

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
