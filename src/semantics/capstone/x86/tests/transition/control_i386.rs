use super::common::{
    I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn,
};

#[test]
fn i386_roundtrip_movsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsb",
        &[0xa4],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3100),
                (I386Register::Edi, 0x3200),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3100, vec![0x41]), (0x3200, vec![0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_movsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsd",
        &[0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3120),
                (I386Register::Edi, 0x3220),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3120, vec![0x78, 0x56, 0x34, 0x12]),
                (0x3220, vec![0x00, 0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_movsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsw",
        &[0x66, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3110),
                (I386Register::Edi, 0x3210),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3110, vec![0x34, 0x12]),
                (0x3210, vec![0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsb",
        &[0xf3, 0xa4],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3800),
                (I386Register::Edi, 0x3900),
                (I386Register::Ecx, 3),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3800, vec![0x41, 0x42, 0x43]),
                (0x3900, vec![0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsw",
        &[0xf3, 0x66, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3810),
                (I386Register::Edi, 0x3910),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![
                (0x380e, vec![0xaa, 0xbb, 0xcc, 0xdd]),
                (0x390c, vec![0x00, 0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsd",
        &[0xf3, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3820),
                (I386Register::Edi, 0x3920),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3820, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14]),
                (0x3920, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_stosb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosb",
        &[0xaa],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_00ab),
                (I386Register::Edi, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3000, vec![0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_stosw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosw",
        &[0x66, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_cdef),
                (I386Register::Edi, 0x3010),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3010, vec![0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_rep_stosw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep stosw",
        &[0xf3, 0x66, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_abcd),
                (I386Register::Edi, 0x3710),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x370c, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_stosd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosd",
        &[0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3020),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3020, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_rep_stosd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep stosd",
        &[0xf3, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edi, 0x3700),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3700, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsw",
        &[0x66, 0xad],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3310),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3310, vec![0xef, 0xbe])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsb",
        &[0xac],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3300),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3300, vec![0xaa])],
        },
    );
}

#[test]
fn i386_roundtrip_scasw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasw",
        &[0x66, 0xaf],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_1234),
                (I386Register::Edi, 0x3410),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3410, vec![0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsd",
        &[0xad],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0000),
                (I386Register::Esi, 0x3320),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
        },
    );
}

#[test]
fn i386_roundtrip_scasd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasd",
        &[0xaf],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3420),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_scasb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasb",
        &[0xae],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0041),
                (I386Register::Edi, 0x3400),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3400, vec![0x41])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsb",
        &[0xa6],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3500),
                (I386Register::Edi, 0x3600),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsw",
        &[0x66, 0xa7],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3510),
                (I386Register::Edi, 0x3610),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsd",
        &[0xa7],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3520),
                (I386Register::Edi, 0x3620),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3520, vec![0x78, 0x56, 0x34, 0x12]),
                (0x3620, vec![0x77, 0x56, 0x34, 0x12]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, al",
        &[0x0f, 0xbe, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3384),
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
fn i386_roundtrip_movsx_eax_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, byte ptr [ebx+4]",
        &[0x0f, 0xbe, 0x43, 0x04],
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
            memory: vec![(0x3004, vec![0x84])],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_word_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, word ptr [ebx+4]",
        &[0x0f, 0xbf, 0x43, 0x04],
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
            memory: vec![(0x3004, vec![0x34, 0xf2])],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_ptr_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, byte ptr [esp+4]",
        &[0x0f, 0xbe, 0x44, 0x24, 0x04],
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
            memory: vec![(0x2ff4, vec![0x84])],
        },
    );
}

#[test]
fn i386_roundtrip_movsx_eax_ptr_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsx eax, byte ptr [ebp-4]",
        &[0x0f, 0xbe, 0x45, 0xfc],
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
            memory: vec![(0x2fec, vec![0x84])],
        },
    );
}

#[test]
fn i386_roundtrip_push_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "push eax",
        &[0x50],
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
            memory: vec![(0x2fec, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_pop_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pop eax",
        &[0x58],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x246,
            memory: vec![(0x2fec, vec![0x78, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_pushfd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pushfd",
        &[0x9c],
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
            memory: vec![(0x2fec, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_popfd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "popfd",
        &[0x9d],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x202,
            memory: vec![(0x2fec, vec![0x46, 0x02, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_ret_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "ret",
        &[0xc3],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x246,
            memory: vec![(0x2fec, vec![0x00, 0x11, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_ret_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "ret 4",
        &[0xc2, 0x04, 0x00],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x246,
            memory: vec![(0x2fec, vec![0x00, 0x11, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_leave_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "leave",
        &[0xc9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2fe0),
                (I386Register::Esp, 0x2fd0),
            ],
            eflags: 0x246,
            memory: vec![(0x2fe0, vec![0xf0, 0x2f, 0x00, 0x00])],
        },
    );
}
