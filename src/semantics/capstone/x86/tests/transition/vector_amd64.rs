use super::common::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
};

#[test]
fn amd64_roundtrip_pxor_xmm0_xmm1_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm1",
        &[0x66, 0x0f, 0xef, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_por_xmm0_xmm1_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "por xmm0, xmm1",
        &[0x66, 0x0f, 0xeb, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
