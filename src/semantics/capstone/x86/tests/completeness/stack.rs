use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn stack_semantics_regressions_stay_complete() {
    let cases = [
        (
            "enter 0x10, 0x00",
            Architecture::I386,
            vec![0xc8, 0x10, 0x00, 0x00],
        ),
        (
            "enter 0x10, 0x01",
            Architecture::I386,
            vec![0xc8, 0x10, 0x00, 0x01],
        ),
        (
            "lock cmpxchg8b qword ptr [eax]",
            Architecture::I386,
            vec![0xf0, 0x0f, 0xc7, 0x08],
        ),
        ("pushal", Architecture::I386, vec![0x60]),
        ("popal", Architecture::I386, vec![0x61]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
