use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn integer_semantics_regressions_stay_complete() {
    let cases = [
        ("aaa", Architecture::I386, vec![0x37]),
        ("aad", Architecture::I386, vec![0xd5, 0x0a]),
        ("aam", Architecture::I386, vec![0xd4, 0x0a]),
        ("aas", Architecture::I386, vec![0x3f]),
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
            "andn eax, ecx, edx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x70, 0xf2, 0xc2],
        ),
        (
            "bzhi eax, ecx, edx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x68, 0xf5, 0xc1],
        ),
        (
            "mulx eax, ebx, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x63, 0xf6, 0xc1],
        ),
        (
            "shlx eax, ebx, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x71, 0xf7, 0xc3],
        ),
        (
            "shrx eax, ebx, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x73, 0xf7, 0xc3],
        ),
        (
            "sarx eax, ebx, ecx",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x72, 0xf7, 0xc3],
        ),
        (
            "rorx eax, ebx, 7",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0x7b, 0xf0, 0xc3, 0x07],
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
        ("bswap eax", Architecture::I386, vec![0x0f, 0xc8]),
        (
            "popcnt eax, ebx",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0xb8, 0xc3],
        ),
        (
            "movbe eax, dword ptr [eax]",
            Architecture::I386,
            vec![0x0f, 0x38, 0xf0, 0x00],
        ),
        (
            "movbe dword ptr [eax], ebx",
            Architecture::I386,
            vec![0x0f, 0x38, 0xf1, 0x18],
        ),
        (
            "adcx eax, ebx",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0xf6, 0xc3],
        ),
        (
            "adox eax, ebx",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x38, 0xf6, 0xc3],
        ),
        (
            "btc eax, 1",
            Architecture::I386,
            vec![0x0f, 0xba, 0xf8, 0x01],
        ),
        ("xadd eax, ebx", Architecture::I386, vec![0x0f, 0xc1, 0xd8]),
        (
            "cmpxchg eax, ebx",
            Architecture::I386,
            vec![0x0f, 0xb1, 0xd8],
        ),
        (
            "cmpxchg16b [rax]",
            Architecture::AMD64,
            vec![0x48, 0x0f, 0xc7, 0x08],
        ),
        ("shl eax, cl", Architecture::I386, vec![0xd3, 0xe0]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
