use super::common::{I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn};

#[test]
fn amd64_roundtrip_xor_eax_eax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "xor eax, eax",
        &[0x31, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Rax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}



#[test]
fn amd64_roundtrip_bsf_rcx_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bsf rcx, rax",
        &[0x48, 0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1000_0000_0000_0040),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_blsi_eax_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "blsi eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xd9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1011000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_blsmsk_eax_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "blsmsk eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xd1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1011000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_blsr_eax_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "blsr eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xc9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1011000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bextr_eax_ecx_edx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bextr eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1110_1100),
                (I386Register::Edx, 0x0000_0201),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bzhi_eax_ecx_edx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bzhi eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0xffff_ffff),
                (I386Register::Edx, 5),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pdep_eax_ebx_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pdep eax, ebx, ecx",
        &[0xc4, 0xe2, 0x63, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ebx, 0b1011),
                (I386Register::Ecx, 0b0011_0101),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pext_eax_ebx_ecx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pext eax, ebx, ecx",
        &[0xc4, 0xe2, 0x62, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ebx, 0b1011),
                (I386Register::Ecx, 0b0011_0101),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pdep_rax_rbx_rcx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pdep rax, rbx, rcx",
        &[0xc4, 0xe2, 0xe3, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0),
                (I386Register::Rbx, 0x0000_0000_0000_000b),
                (I386Register::Rcx, 0x8000_0000_0000_0035),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pext_rax_rbx_rcx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pext rax, rbx, rcx",
        &[0xc4, 0xe2, 0xe2, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0),
                (I386Register::Rbx, 0x8000_0000_0000_000b),
                (I386Register::Rcx, 0x8000_0000_0000_0035),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bsr_rcx_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bsr rcx, rax",
        &[0x48, 0x0f, 0xbd, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1000_0000_0000_0040),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_bswap_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bswap rax",
        &[0x48, 0x0f, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x247,
            memory: vec![],
        },
    );
}
