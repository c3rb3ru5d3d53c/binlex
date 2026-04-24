use super::super::support::{I386Fixture, I386Register, WideI386Fixture, interpret_amd64_wide_semantics};

fn vec256(low: [u8; 16], high: [u8; 16]) -> Vec<u8> {
    [low.as_slice(), high.as_slice()].concat()
}

// Unicorn 2.1.5 rejects these AVX YMM forms with `INSN_INVALID`, so keep them
// as semantics-only wide regressions until a reliable execution oracle is
// available for 256-bit x86 vectors in this environment.
#[test]
fn vector_ymm_semantics_wide_regressions() {
    let ymm0 = vec256(
        [
            0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x11, 0x22,
        ],
        [
            0x01, 0x81, 0x02, 0x82, 0x03, 0x83, 0x04, 0x84, 0x05, 0x85, 0x06, 0x86, 0x07, 0x87,
            0x08, 0x88,
        ],
    );
    let ymm1 = vec256(
        [
            0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0x99, 0x88,
        ],
        [
            0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69,
            0x87, 0x78,
        ],
    );
    let ymm2 = vec256(
        [
            0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
            0x9b, 0xdf,
        ],
        [
            0x24, 0x42, 0x66, 0x81, 0xa5, 0xc3, 0xe7, 0xff, 0x18, 0x36, 0x54, 0x72, 0x90, 0xab,
            0xcd, 0xef,
        ],
    );

    let cases = [
        (
            "vextracti128 xmm0, ymm1, 1",
            vec![0xc4, 0xe3, 0x7d, 0x39, 0xc8, 0x01],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![(I386Register::Xmm0, 0)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![(I386Register::Ymm1, ymm1.clone())],
            },
            Some((
                "xmm0",
                vec![
                    0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96,
                    0x69, 0x87, 0x78,
                ],
            )),
            None,
        ),
        (
            "vperm2i128 ymm0, ymm2, ymm1, 0x31",
            vec![0xc4, 0xe3, 0x6d, 0x46, 0xc1, 0x31],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1.clone()),
                    (I386Register::Ymm2, ymm2.clone()),
                ],
            },
            Some((
                "ymm0",
                vec![
                    0x24, 0x42, 0x66, 0x81, 0xa5, 0xc3, 0xe7, 0xff, 0x18, 0x36, 0x54, 0x72, 0x90,
                    0xab, 0xcd, 0xef, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b,
                    0xa5, 0x5a, 0x96, 0x69, 0x87, 0x78,
                ],
            )),
            None,
        ),
        (
            "vpermq ymm0, ymm1, 0x1b",
            vec![0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1.clone()),
                ],
            },
            Some((
                "ymm0",
                vec![
                    0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69, 0x87, 0x78, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2,
                    0x2d, 0xc3, 0x3c, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x01, 0xff,
                    0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc,
                ],
            )),
            None,
        ),
        (
            "vpshufd ymm0, ymm1, 0x1b",
            vec![0xc5, 0xfd, 0x70, 0xc1, 0x1b],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1.clone()),
                ],
            },
            Some((
                "ymm0",
                vec![
                    0x11, 0x00, 0x99, 0x88, 0x55, 0x44, 0x33, 0x22, 0x03, 0xfd, 0x04, 0xfc, 0x01,
                    0xff, 0x02, 0xfe, 0x96, 0x69, 0x87, 0x78, 0xb4, 0x4b, 0xa5, 0x5a, 0xd2, 0x2d,
                    0xc3, 0x3c, 0xf0, 0x0f, 0xe1, 0x1e,
                ],
            )),
            None,
        ),
        (
            "vptest ymm0, ymm1",
            vec![0xc4, 0xe2, 0x7d, 0x17, 0xc1],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, ymm0.clone()),
                    (I386Register::Ymm1, ymm1.clone()),
                ],
            },
            None,
            Some((false, false)),
        ),
        (
            "vpmovmskb eax, ymm0",
            vec![0xc5, 0xfd, 0xd7, 0xc0],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![(I386Register::Eax, 0)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![(I386Register::Ymm0, ymm0.clone())],
            },
            Some(("eax", vec![0x02, 0x3f, 0xaa, 0xaa])),
            None,
        ),
        (
            "vpunpcklbw ymm0, ymm2, ymm1",
            vec![0xc5, 0xed, 0x60, 0xc1],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1),
                    (I386Register::Ymm2, ymm2),
                ],
            },
            Some((
                "ymm0",
                vec![
                    0xde, 0x01, 0xad, 0xff, 0xbe, 0x02, 0xef, 0xfe, 0x10, 0x03, 0x32, 0xfd, 0x54,
                    0x04, 0x76, 0xfc, 0x24, 0xf0, 0x42, 0x0f, 0x66, 0xe1, 0x81, 0x1e, 0xa5, 0xd2,
                    0xc3, 0x2d, 0xe7, 0xc3, 0xff, 0x3c,
                ],
            )),
            None,
        ),
    ];

    for (name, bytes, fixture, expected_register, expected_flags) in cases {
        let (registers, flags) = interpret_amd64_wide_semantics(name, &bytes, fixture);
        if let Some((register, expected)) = expected_register {
            let actual = registers.get(register).unwrap_or_else(|| {
                panic!(
                    "{name}: register {register} should exist; available: {:?}",
                    registers.keys().collect::<Vec<_>>()
                )
            });
            assert_eq!(
                actual, &expected,
                "{name}: register {register} mismatch",
            );
        }
        if let Some((zf, cf)) = expected_flags {
            assert_eq!(flags.zf, zf, "{name}: zf mismatch");
            assert_eq!(flags.cf, cf, "{name}: cf mismatch");
        }
    }
}
