use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn,
    assert_i386_semantics_match_unicorn,
};

#[test]
fn bit_semantics_match_unicorn_transitions() {
    let i386_cases = [
        (
            "bt eax, 1",
            vec![0x0f, 0xba, 0xe0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0b10)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "bts eax, 1",
            vec![0x0f, 0xba, 0xe8, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "btr eax, 1",
            vec![0x0f, 0xba, 0xf0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0b10)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "btc eax, 1",
            vec![0x0f, 0xba, 0xf8, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0b10)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "bsf ecx, eax",
            vec![0x0f, 0xbc, 0xc8],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "bsr ecx, eax",
            vec![0x0f, 0xbd, 0xc8],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in i386_cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }

    let amd64_cases = [
        (
            "tzcnt ecx, eax",
            vec![0xf3, 0x0f, 0xbc, 0xc8],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "lzcnt ecx, eax",
            vec![0xf3, 0x0f, 0xbd, 0xc8],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "blsi eax, ecx",
            vec![0xc4, 0xe2, 0x78, 0xf3, 0xd9],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Ecx, 0b1011000)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "blsmsk eax, ecx",
            vec![0xc4, 0xe2, 0x78, 0xf3, 0xd1],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Ecx, 0b1011000)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "blsr eax, ecx",
            vec![0xc4, 0xe2, 0x78, 0xf3, 0xc9],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Ecx, 0b1011000)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "bextr eax, ecx, edx",
            vec![0xc4, 0xe2, 0x68, 0xf7, 0xc1],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ecx, 0b1110_1100),
                    (I386Register::Edx, 0x0000_0201),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "bzhi eax, ecx, edx",
            vec![0xc4, 0xe2, 0x68, 0xf5, 0xc1],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ecx, 0xffff_ffff),
                    (I386Register::Edx, 5),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pdep eax, ebx, ecx",
            vec![0xc4, 0xe2, 0x63, 0xf5, 0xc1],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ebx, 0b1011),
                    (I386Register::Ecx, 0b0011_0101),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pext eax, ebx, ecx",
            vec![0xc4, 0xe2, 0x62, 0xf5, 0xc1],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ebx, 0b1101_0110),
                    (I386Register::Ecx, 0b0011_0101),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in amd64_cases {
        assert_amd64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
