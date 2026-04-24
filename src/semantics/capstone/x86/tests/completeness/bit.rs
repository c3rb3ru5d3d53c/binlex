use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn bit_semantics_regressions_stay_complete() {
    let cases = [
        ("bsf ecx, eax", Architecture::I386, vec![0x0f, 0xbc, 0xc8]),
        ("bsr ecx, eax", Architecture::I386, vec![0x0f, 0xbd, 0xc8]),
        (
            "tzcnt ecx, eax",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0xbc, 0xc8],
        ),
        (
            "lzcnt ecx, eax",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0xbd, 0xc8],
        ),
        (
            "blsi eax, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x78, 0xf3, 0xd9],
        ),
        (
            "blsmsk eax, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x78, 0xf3, 0xd1],
        ),
        (
            "blsr eax, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x78, 0xf3, 0xc9],
        ),
        (
            "bextr eax, ecx, 0x21",
            Architecture::AMD64,
            vec![0x8f, 0xea, 0x78, 0x10, 0xc1, 0x21, 0x00, 0x00, 0x00],
        ),
        (
            "bzhi eax, ecx, edx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x68, 0xf5, 0xc1],
        ),
        (
            "pdep eax, ebx, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x63, 0xf5, 0xc1],
        ),
        (
            "pext eax, ebx, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x62, 0xf5, 0xc1],
        ),
        (
            "btc eax, 1",
            Architecture::I386,
            vec![0x0f, 0xba, 0xf8, 0x01],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
