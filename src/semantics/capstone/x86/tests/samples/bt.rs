use super::super::support::{I386Fixture, I386Register, assert_i386_semantics_match_unicorn};

#[test]
fn bt_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "bt eax, 1",
        &[0x0f, 0xba, 0xe0, 0x01],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0b10)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
