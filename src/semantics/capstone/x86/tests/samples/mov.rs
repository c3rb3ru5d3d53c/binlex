use super::super::support::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_i386_instruction_roundtrip_match_unicorn,
};

#[test]
fn i386_roundtrip_mov_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, ebx",
        &[0x89, 0xd8],
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
            eflags: 0x246,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_mov_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "mov rax, rbx",
        &[0x48, 0x89, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ptr_ebx_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, [ebx+4]",
        &[0x8b, 0x43, 0x04],
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
            memory: vec![(0x3004, vec![0x78, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_mov_ptr_ebx_plus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov [ebx+4], eax",
        &[0x89, 0x43, 0x04],
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
            memory: vec![(0x3004, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ptr_esp_plus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, [esp+4]",
        &[0x8b, 0x44, 0x24, 0x04],
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
            memory: vec![(0x2ff4, vec![0x78, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_mov_ptr_esp_plus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov [esp+4], eax",
        &[0x89, 0x44, 0x24, 0x04],
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
            memory: vec![(0x2ff4, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_mov_eax_ptr_ebp_minus_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov eax, [ebp-4]",
        &[0x8b, 0x45, 0xfc],
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
            memory: vec![(0x2fec, vec![0x78, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_mov_ptr_ebp_minus_4_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mov [ebp-4], eax",
        &[0x89, 0x45, 0xfc],
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
fn amd64_roundtrip_mov_rax_ptr_rbx_plus_4_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "mov rax, [rbx+4]",
        &[0x48, 0x8b, 0x43, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: vec![(0x3004, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
        },
    );
}
