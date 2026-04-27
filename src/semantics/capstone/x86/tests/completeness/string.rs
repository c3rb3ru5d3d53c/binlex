use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn string_semantics_regressions_stay_complete() {
    let cases = [
        ("stosq", Architecture::AMD64, vec![0x48, 0xab]),
        ("movsq", Architecture::AMD64, vec![0x48, 0xa5]),
        ("lodsq", Architecture::AMD64, vec![0x48, 0xad]),
        ("scasq", Architecture::AMD64, vec![0x48, 0xaf]),
        ("cmpsq", Architecture::AMD64, vec![0x48, 0xa7]),
        ("rep movsq", Architecture::AMD64, vec![0xf3, 0x48, 0xa5]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
