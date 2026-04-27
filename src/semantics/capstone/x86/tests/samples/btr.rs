use super::super::support::{I386Fixture, I386Register, assert_i386_semantics_match_unicorn};

#[test]
fn btr_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "btr eax, 1",
        &[0x0f, 0xba, 0xf0, 0x01],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0b10)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
