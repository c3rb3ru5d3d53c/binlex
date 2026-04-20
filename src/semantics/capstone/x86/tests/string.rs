use super::common::assert_complete_semantics;
use crate::Architecture;

#[test]
fn string_semantics_regressions_stay_complete() {
    let cases = [
        ("stosb", Architecture::I386, vec![0xaa]),
        ("stosw", Architecture::I386, vec![0x66, 0xab]),
        ("stosd", Architecture::I386, vec![0xab]),
        ("stosq", Architecture::AMD64, vec![0x48, 0xab]),
        ("movsb", Architecture::I386, vec![0xa4]),
        ("movsw", Architecture::I386, vec![0x66, 0xa5]),
        ("movsd", Architecture::I386, vec![0xa5]),
        ("movsq", Architecture::AMD64, vec![0x48, 0xa5]),
        ("lodsb", Architecture::I386, vec![0xac]),
        ("lodsw", Architecture::I386, vec![0x66, 0xad]),
        ("lodsd", Architecture::I386, vec![0xad]),
        ("lodsq", Architecture::AMD64, vec![0x48, 0xad]),
        ("scasb", Architecture::I386, vec![0xae]),
        ("scasw", Architecture::I386, vec![0x66, 0xaf]),
        ("scasd", Architecture::I386, vec![0xaf]),
        ("scasq", Architecture::AMD64, vec![0x48, 0xaf]),
        ("cmpsb", Architecture::I386, vec![0xa6]),
        ("cmpsw", Architecture::I386, vec![0x66, 0xa7]),
        ("cmpsd", Architecture::I386, vec![0xa7]),
        ("cmpsq", Architecture::AMD64, vec![0x48, 0xa7]),
        ("rep stosd", Architecture::I386, vec![0xf3, 0xab]),
        ("rep stosw", Architecture::I386, vec![0xf3, 0x66, 0xab]),
        ("rep movsb", Architecture::I386, vec![0xf3, 0xa4]),
        ("rep movsw", Architecture::I386, vec![0xf3, 0x66, 0xa5]),
        ("rep movsd", Architecture::I386, vec![0xf3, 0xa5]),
        ("rep movsq", Architecture::AMD64, vec![0xf3, 0x48, 0xa5]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
