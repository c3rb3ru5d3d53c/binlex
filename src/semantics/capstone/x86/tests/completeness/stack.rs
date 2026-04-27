use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn stack_semantics_regressions_stay_complete() {
    let cases = [
        (
            "lock cmpxchg8b qword ptr [eax]",
            Architecture::I386,
            vec![0xf0, 0x0f, 0xc7, 0x08],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
