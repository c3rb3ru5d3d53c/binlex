use super::common::{
    I386Fixture, I386Register, assert_complete_semantics, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn integer_semantics_regressions_stay_complete() {
    let cases = [
        ("aaa", Architecture::I386, vec![0x37]),
        ("aad", Architecture::I386, vec![0xd5, 0x0a]),
        ("aam", Architecture::I386, vec![0xd4, 0x0a]),
        ("aas", Architecture::I386, vec![0x3f]),
        ("add eax, ebx", Architecture::I386, vec![0x01, 0xd8]),
        ("adc eax, ebx", Architecture::I386, vec![0x11, 0xd8]),
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
        ("rcl eax, 1", Architecture::I386, vec![0xd1, 0xd0]),
        ("rcr eax, 1", Architecture::I386, vec![0xd1, 0xd8]),
        ("rcl rax, 1", Architecture::AMD64, vec![0x48, 0xd1, 0xd0]),
        ("rcr rax, 1", Architecture::AMD64, vec![0x48, 0xd1, 0xd8]),
        (
            "shld eax, edx, cl",
            Architecture::I386,
            vec![0x0f, 0xa5, 0xd0],
        ),
        (
            "shrd eax, edx, cl",
            Architecture::I386,
            vec![0x0f, 0xad, 0xd0],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn integer_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "add eax, ebx",
            vec![0x01, 0xd8],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x7fff_ffff),
                    (I386Register::Ebx, 0x0000_0001),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "adc eax, ebx",
            vec![0x11, 0xd8],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xffff_ffff),
                    (I386Register::Ebx, 0x0000_0000),
                ],
                eflags: (1 << 1) | (1 << 0),
                memory: vec![],
            },
        ),
        (
            "sub eax, ebx",
            vec![0x29, 0xd8],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_0000),
                    (I386Register::Ebx, 0x0000_0001),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "cmp eax, ebx",
            vec![0x39, 0xd8],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x8000_0000),
                    (I386Register::Ebx, 0x0000_0001),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "inc eax",
            vec![0x40],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x7fff_ffff)],
                eflags: (1 << 1) | (1 << 0),
                memory: vec![],
            },
        ),
        (
            "dec eax",
            vec![0x48],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x8000_0000)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "neg eax",
            vec![0xf7, 0xd8],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x8000_0000)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "not eax",
            vec![0xf7, 0xd0],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x1234_5678)],
                eflags: (1 << 1) | (1 << 6),
                memory: vec![],
            },
        ),
        (
            "bswap eax",
            vec![0x0f, 0xc8],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x1234_5678)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "xadd eax, ebx",
            vec![0x0f, 0xc1, 0xd8],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x7fff_ffff),
                    (I386Register::Ebx, 0x0000_0001),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "cmpxchg eax, ebx",
            vec![0x0f, 0xb1, 0xd8],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Ebx, 0x9abc_def0),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "div ecx",
            vec![0xf7, 0xf1],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 100),
                    (I386Register::Ecx, 5),
                    (I386Register::Edx, 0),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "idiv ecx",
            vec![0xf7, 0xf9],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xffff_ff9c),
                    (I386Register::Ecx, 5),
                    (I386Register::Edx, 0xffff_ffff),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}
