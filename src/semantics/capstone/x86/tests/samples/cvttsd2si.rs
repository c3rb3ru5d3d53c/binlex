use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
};
use crate::Architecture;

#[test]
fn cvttsd2si_semantics_stay_complete() {
    assert_complete_semantics(
        "cvttsd2si eax, xmm0",
        Architecture::AMD64,
        &[0xf2, 0x0f, 0x2c, 0xc0],
    );
}

#[test]
fn cvttsd2si_semantics_match_unicorn_transitions() {
    assert_amd64_semantics_match_unicorn(
        "cvttsd2si eax, xmm0",
        &[0xf2, 0x0f, 0x2c, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Xmm0, 0x1122_3344_5566_7788_4045_6000_0000_0000),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
