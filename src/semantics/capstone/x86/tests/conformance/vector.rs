use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn};

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

#[test]
fn vector_integer_and_move_semantics_match_unicorn_transitions() {
    let xmm0 = vec128([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
        0x22,
    ]);
    let xmm1 = vec128([
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
        0x88,
    ]);
    let mask = vec128([
        0x00, 0x81, 0x02, 0x83, 0x04, 0x85, 0x06, 0x87, 0x08, 0x89, 0x0a, 0x8b, 0x0c, 0x8d, 0x0e,
        0x8f,
    ]);
    let mem128 = vec![
        0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57, 0x9b,
        0xdf,
    ];

    let cases = [
        (
            "movapd xmm0, xmm1",
            vec![0x66, 0x0f, 0x28, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movntdq xmmword ptr [rax], xmm0",
            vec![0x66, 0x0f, 0xe7, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0; 16])],
            },
        ),
        (
            "lddqu xmm0, xmmword ptr [rax]",
            vec![0xf2, 0x0f, 0xf0, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, 0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, mem128.clone())],
            },
        ),
        (
            "movddup xmm0, xmm1",
            vec![0xf2, 0x0f, 0x12, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movshdup xmm0, xmm1",
            vec![0xf3, 0x0f, 0x16, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movsldup xmm0, xmm1",
            vec![0xf3, 0x0f, 0x12, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "andpd xmm0, xmm1",
            vec![0x66, 0x0f, 0x54, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "andnps xmm0, xmm1",
            vec![0x0f, 0x55, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pandn xmm0, xmm1",
            vec![0x66, 0x0f, 0xdf, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "paddb xmm0, xmm1",
            vec![0x66, 0x0f, 0xfc, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pavgb xmm0, xmm1",
            vec![0x66, 0x0f, 0xe0, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "psubw xmm0, xmm1",
            vec![0x66, 0x0f, 0xf9, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "psllq xmm0, 1",
            vec![0x66, 0x0f, 0x73, 0xf0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pcmpeqb xmm0, xmm1",
            vec![0x66, 0x0f, 0x74, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pcmpgtw xmm0, xmm1",
            vec![0x66, 0x0f, 0x65, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmaxub xmm0, xmm1",
            vec![0x66, 0x0f, 0xde, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pminsw xmm0, xmm1",
            vec![0x66, 0x0f, 0xea, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmaddwd xmm0, xmm1",
            vec![0x66, 0x0f, 0xf5, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmulhw xmm0, xmm1",
            vec![0x66, 0x0f, 0xe5, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmuludq xmm0, xmm1",
            vec![0x66, 0x0f, 0xf4, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "packsswb xmm0, xmm1",
            vec![0x66, 0x0f, 0x63, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pextrd eax, xmm0, 1",
            vec![0x66, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pinsrd xmm0, eax, 1",
            vec![0x66, 0x0f, 0x3a, 0x22, 0xc0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x1234_5678), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmovmskb eax, xmm0",
            vec![0x66, 0x0f, 0xd7, 0xc0],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "ptest xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x17, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movhlps xmm0, xmm1",
            vec![0x0f, 0x12, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movhpd xmm0, qword ptr [rax]",
            vec![0x66, 0x0f, 0x16, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, mem128[..8].to_vec())],
            },
        ),
        (
            "pshufb xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x00, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, mask)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmovsxbw xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x20, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmovzxdq xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x35, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_amd64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
