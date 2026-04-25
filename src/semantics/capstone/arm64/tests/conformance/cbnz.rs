use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cbnz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cbnz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x0", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x0", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w0", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x1", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w1", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x2", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x2", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w2", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x3", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w3", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x4", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w4", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x5", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w5", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x6", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w6", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x7", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w7", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x8", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w8", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x9, #0x10",
            vec![0x89, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x9", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x9, #0x10",
            vec![0x89, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x9", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w9, #0x10",
            vec![0x89, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w9", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w9, #0x10",
            vec![0x89, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w9", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x10, #0x10",
            vec![0x8a, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x10", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x10, #0x10",
            vec![0x8a, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x10", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w10, #0x10",
            vec![0x8a, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w10", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w10, #0x10",
            vec![0x8a, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w10", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x11, #0x10",
            vec![0x8b, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x11", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x11, #0x10",
            vec![0x8b, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x11", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w11, #0x10",
            vec![0x8b, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w11", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w11, #0x10",
            vec![0x8b, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w11", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x12, #0x10",
            vec![0x8c, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x12", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x12, #0x10",
            vec![0x8c, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x12", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w12, #0x10",
            vec![0x8c, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w12", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w12, #0x10",
            vec![0x8c, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w12", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x13, #0x10",
            vec![0x8d, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x13", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x13, #0x10",
            vec![0x8d, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x13", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w13, #0x10",
            vec![0x8d, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w13", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w13, #0x10",
            vec![0x8d, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w13", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x14, #0x10",
            vec![0x8e, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x14", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x14, #0x10",
            vec![0x8e, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x14", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w14, #0x10",
            vec![0x8e, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w14", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w14, #0x10",
            vec![0x8e, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w14", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x15, #0x10",
            vec![0x8f, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x15", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x15, #0x10",
            vec![0x8f, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x15", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w15, #0x10",
            vec![0x8f, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w15", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w15, #0x10",
            vec![0x8f, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w15", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x16, #0x10",
            vec![0x90, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x16", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x16, #0x10",
            vec![0x90, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x16", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w16, #0x10",
            vec![0x90, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w16", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w16, #0x10",
            vec![0x90, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w16", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x17, #0x10",
            vec![0x91, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x17", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x17, #0x10",
            vec![0x91, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x17", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w17, #0x10",
            vec![0x91, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w17", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w17, #0x10",
            vec![0x91, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w17", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x18, #0x10",
            vec![0x92, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x18", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x18, #0x10",
            vec![0x92, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x18", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w18, #0x10",
            vec![0x92, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w18", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w18, #0x10",
            vec![0x92, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w18", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x19, #0x10",
            vec![0x93, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x19", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x19, #0x10",
            vec![0x93, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x19", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w19, #0x10",
            vec![0x93, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w19", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w19, #0x10",
            vec![0x93, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w19", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x20, #0x10",
            vec![0x94, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x20", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x20, #0x10",
            vec![0x94, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x20", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w20, #0x10",
            vec![0x94, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w20", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w20, #0x10",
            vec![0x94, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w20", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x21, #0x10",
            vec![0x95, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x21", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x21, #0x10",
            vec![0x95, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x21", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w21, #0x10",
            vec![0x95, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w21", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w21, #0x10",
            vec![0x95, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w21", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x22, #0x10",
            vec![0x96, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x22", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x22, #0x10",
            vec![0x96, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x22", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w22, #0x10",
            vec![0x96, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w22", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w22, #0x10",
            vec![0x96, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w22", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x23, #0x10",
            vec![0x97, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x23", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x23, #0x10",
            vec![0x97, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x23", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w23, #0x10",
            vec![0x97, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w23", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w23, #0x10",
            vec![0x97, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w23", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x24, #0x10",
            vec![0x98, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x24", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x24, #0x10",
            vec![0x98, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x24", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w24, #0x10",
            vec![0x98, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w24", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w24, #0x10",
            vec![0x98, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w24", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x25, #0x10",
            vec![0x99, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x25", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x25, #0x10",
            vec![0x99, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x25", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w25, #0x10",
            vec![0x99, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w25", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w25, #0x10",
            vec![0x99, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w25", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x26, #0x10",
            vec![0x9a, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x26", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x26, #0x10",
            vec![0x9a, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x26", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w26, #0x10",
            vec![0x9a, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w26", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w26, #0x10",
            vec![0x9a, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w26", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x27, #0x10",
            vec![0x9b, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x27", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x27, #0x10",
            vec![0x9b, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x27", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w27, #0x10",
            vec![0x9b, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w27", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w27, #0x10",
            vec![0x9b, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w27", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x28, #0x10",
            vec![0x9c, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x28", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x28, #0x10",
            vec![0x9c, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x28", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w28, #0x10",
            vec![0x9c, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w28", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w28, #0x10",
            vec![0x9c, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w28", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x29, #0x10",
            vec![0x9d, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x29", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x29, #0x10",
            vec![0x9d, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x29", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w29, #0x10",
            vec![0x9d, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w29", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w29, #0x10",
            vec![0x9d, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w29", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x30, #0x10",
            vec![0x9e, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x30", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x30, #0x10",
            vec![0x9e, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x30", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w30, #0x10",
            vec![0x9e, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w30", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w30, #0x10",
            vec![0x9e, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w30", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x0", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x0", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w0", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x1", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w1", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x2", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x2", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w2", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x3", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w3", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x4", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w4", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x5", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w5", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x6", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w6", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x7", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w7", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x8", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb5],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
(
            "cbnz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w8", 1)],
                memory: vec![],
            },
        ),
(
            "cbnz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x35],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
