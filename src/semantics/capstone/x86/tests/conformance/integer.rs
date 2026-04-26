use super::super::support::{I386Fixture, I386Register, assert_i386_semantics_match_unicorn};

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
