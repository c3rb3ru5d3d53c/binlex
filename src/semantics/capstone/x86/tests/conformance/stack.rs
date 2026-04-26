use super::super::support::{I386Fixture, I386Register, assert_i386_semantics_match_unicorn};

#[test]
fn stack_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "push eax",
            vec![0x50],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Esp, 0x2800),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pop eax",
            vec![0x58],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esp, 0x2800),
                ],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x78, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "pushal",
            vec![0x60],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1111_1111),
                    (I386Register::Ecx, 0x2222_2222),
                    (I386Register::Edx, 0x3333_3333),
                    (I386Register::Ebx, 0x4444_4444),
                    (I386Register::Esp, 0x2840),
                    (I386Register::Ebp, 0x5555_5555),
                    (I386Register::Esi, 0x6666_6666),
                    (I386Register::Edi, 0x7777_7777),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "popal",
            vec![0x61],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ecx, 0),
                    (I386Register::Edx, 0),
                    (I386Register::Ebx, 0),
                    (I386Register::Esp, 0x2800),
                    (I386Register::Ebp, 0),
                    (I386Register::Esi, 0),
                    (I386Register::Edi, 0),
                ],
                eflags: 1 << 1,
                memory: vec![(
                    0x2800,
                    vec![
                        0x77, 0x77, 0x77, 0x77, // edi
                        0x66, 0x66, 0x66, 0x66, // esi
                        0x55, 0x55, 0x55, 0x55, // ebp
                        0x40, 0x28, 0x00, 0x00, // skipped esp slot
                        0x44, 0x44, 0x44, 0x44, // ebx
                        0x33, 0x33, 0x33, 0x33, // edx
                        0x22, 0x22, 0x22, 0x22, // ecx
                        0x11, 0x11, 0x11, 0x11, // eax
                    ],
                )],
            },
        ),
        (
            "leave",
            vec![0xc9],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "enter 0x10, 0x00",
            vec![0xc8, 0x10, 0x00, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "enter 0x10, 0x01",
            vec![0xc8, 0x10, 0x00, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}
