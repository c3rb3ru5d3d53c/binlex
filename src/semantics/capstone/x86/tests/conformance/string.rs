use super::super::support::{
    I386Fixture, I386Register, assert_i386_semantics_match_unicorn,
};

#[test]
fn string_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "stosb",
            vec![0xaa],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_00ab),
                    (I386Register::Edi, 0x3000),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![],
            },
        ),
        (
            "stosw",
            vec![0x66, 0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_cdef),
                    (I386Register::Edi, 0x3010),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "stosd",
            vec![0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Edi, 0x3020),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movsb",
            vec![0xa4],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3100), (I386Register::Edi, 0x3200)],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3100, vec![0x41])],
            },
        ),
        (
            "movsw",
            vec![0x66, 0xa5],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3110), (I386Register::Edi, 0x3210)],
                eflags: 1 << 1,
                memory: vec![(0x3110, vec![0x34, 0x12])],
            },
        ),
        (
            "movsd",
            vec![0xa5],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3120), (I386Register::Edi, 0x3220)],
                eflags: 1 << 1,
                memory: vec![(0x3120, vec![0x78, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "lodsb",
            vec![0xac],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esi, 0x3300),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3300, vec![0xaa])],
            },
        ),
        (
            "lodsw",
            vec![0x66, 0xad],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esi, 0x3310),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3310, vec![0xef, 0xbe])],
            },
        ),
        (
            "lodsd",
            vec![0xad],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Esi, 0x3320)],
                eflags: 1 << 1,
                memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "scasb",
            vec![0xae],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_0041),
                    (I386Register::Edi, 0x3400),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3400, vec![0x41])],
            },
        ),
        (
            "scasw",
            vec![0x66, 0xaf],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_1234),
                    (I386Register::Edi, 0x3410),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3410, vec![0x34, 0x12])],
            },
        ),
        (
            "scasd",
            vec![0xaf],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Edi, 0x3420),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "cmpsb",
            vec![0xa6],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3500), (I386Register::Edi, 0x3600)],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
            },
        ),
        (
            "cmpsw",
            vec![0x66, 0xa7],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3510), (I386Register::Edi, 0x3610)],
                eflags: 1 << 1,
                memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
            },
        ),
        (
            "cmpsd",
            vec![0xa7],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3520), (I386Register::Edi, 0x3620)],
                eflags: 1 << 1,
                memory: vec![
                    (0x3520, vec![0x78, 0x56, 0x34, 0x12]),
                    (0x3620, vec![0x77, 0x56, 0x34, 0x12]),
                ],
            },
        ),
        (
            "rep stosd",
            vec![0xf3, 0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Edi, 0x3700),
                    (I386Register::Ecx, 2),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "rep stosw",
            vec![0xf3, 0x66, 0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_abcd),
                    (I386Register::Edi, 0x3710),
                    (I386Register::Ecx, 2),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![],
            },
        ),
        (
            "rep movsb",
            vec![0xf3, 0xa4],
            I386Fixture {
                registers: vec![
                    (I386Register::Esi, 0x3800),
                    (I386Register::Edi, 0x3900),
                    (I386Register::Ecx, 3),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3800, vec![0x41, 0x42, 0x43])],
            },
        ),
        (
            "rep movsw",
            vec![0xf3, 0x66, 0xa5],
            I386Fixture {
                registers: vec![
                    (I386Register::Esi, 0x3810),
                    (I386Register::Edi, 0x3910),
                    (I386Register::Ecx, 2),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x380e, vec![0xaa, 0xbb, 0xcc, 0xdd])],
            },
        ),
        (
            "rep movsd",
            vec![0xf3, 0xa5],
            I386Fixture {
                registers: vec![
                    (I386Register::Esi, 0x3820),
                    (I386Register::Edi, 0x3920),
                    (I386Register::Ecx, 2),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3820, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14])],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}
