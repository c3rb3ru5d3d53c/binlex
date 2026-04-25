use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn tbz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "tbz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w0", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w1", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x1, #35, #0x10",
            vec![0x81, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x1, #35, #0x10",
            vec![0x81, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w2", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x2, #35, #0x10",
            vec![0x82, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x2", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x2, #35, #0x10",
            vec![0x82, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x2", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w3", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x3, #35, #0x10",
            vec![0x83, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x3, #35, #0x10",
            vec![0x83, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x3", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w4", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x4, #35, #0x10",
            vec![0x84, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x4, #35, #0x10",
            vec![0x84, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x4", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w5", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x5, #35, #0x10",
            vec![0x85, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x5, #35, #0x10",
            vec![0x85, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x5", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w6", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x6, #35, #0x10",
            vec![0x86, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x6, #35, #0x10",
            vec![0x86, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x6", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w7", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x7, #35, #0x10",
            vec![0x87, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x7, #35, #0x10",
            vec![0x87, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x7", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w8", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x8, #35, #0x10",
            vec![0x88, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x8, #35, #0x10",
            vec![0x88, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x8", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w9, #3, #0x10",
            vec![0x89, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w9", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w9, #3, #0x10",
            vec![0x89, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w9", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x9, #35, #0x10",
            vec![0x89, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x9", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x9, #35, #0x10",
            vec![0x89, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x9", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w10, #3, #0x10",
            vec![0x8a, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w10", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w10, #3, #0x10",
            vec![0x8a, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w10", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x10, #35, #0x10",
            vec![0x8a, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x10", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x10, #35, #0x10",
            vec![0x8a, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x10", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w11, #3, #0x10",
            vec![0x8b, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w11", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w11, #3, #0x10",
            vec![0x8b, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w11", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x11, #35, #0x10",
            vec![0x8b, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x11", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x11, #35, #0x10",
            vec![0x8b, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x11", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w12, #3, #0x10",
            vec![0x8c, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w12", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w12, #3, #0x10",
            vec![0x8c, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w12", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x12, #35, #0x10",
            vec![0x8c, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x12", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x12, #35, #0x10",
            vec![0x8c, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x12", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w13, #3, #0x10",
            vec![0x8d, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w13", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w13, #3, #0x10",
            vec![0x8d, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w13", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x13, #35, #0x10",
            vec![0x8d, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x13", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x13, #35, #0x10",
            vec![0x8d, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x13", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w14, #3, #0x10",
            vec![0x8e, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w14", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w14, #3, #0x10",
            vec![0x8e, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w14", 8)],
                memory: vec![],
            },
        ),
(
            "tbz x14, #35, #0x10",
            vec![0x8e, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x14", 0)],
                memory: vec![],
            },
        ),
(
            "tbz x14, #35, #0x10",
            vec![0x8e, 0x00, 0x18, 0xb6],
            Arm64Fixture {
                registers: vec![("x14", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbz w15, #3, #0x10",
            vec![0x8f, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w15", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w15, #3, #0x10",
            vec![0x8f, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w15", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w16, #3, #0x10",
            vec![0x90, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w16", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w16, #3, #0x10",
            vec![0x90, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w16", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w17, #3, #0x10",
            vec![0x91, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w17", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w17, #3, #0x10",
            vec![0x91, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w17", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w18, #3, #0x10",
            vec![0x92, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w18", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w18, #3, #0x10",
            vec![0x92, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w18", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w19, #3, #0x10",
            vec![0x93, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w19", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w19, #3, #0x10",
            vec![0x93, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w19", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w20, #3, #0x10",
            vec![0x94, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w20", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w20, #3, #0x10",
            vec![0x94, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w20", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w21, #3, #0x10",
            vec![0x95, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w21", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w21, #3, #0x10",
            vec![0x95, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w21", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w22, #3, #0x10",
            vec![0x96, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w22", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w22, #3, #0x10",
            vec![0x96, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w22", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w23, #3, #0x10",
            vec![0x97, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w23", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w23, #3, #0x10",
            vec![0x97, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w23", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w24, #3, #0x10",
            vec![0x98, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w24", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w24, #3, #0x10",
            vec![0x98, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w24", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w25, #3, #0x10",
            vec![0x99, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w25", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w25, #3, #0x10",
            vec![0x99, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w25", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w26, #3, #0x10",
            vec![0x9a, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w26", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w26, #3, #0x10",
            vec![0x9a, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w26", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w27, #3, #0x10",
            vec![0x9b, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w27", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w27, #3, #0x10",
            vec![0x9b, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w27", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w28, #3, #0x10",
            vec![0x9c, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w28", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w28, #3, #0x10",
            vec![0x9c, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w28", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w29, #3, #0x10",
            vec![0x9d, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w29", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w29, #3, #0x10",
            vec![0x9d, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w29", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w30, #3, #0x10",
            vec![0x9e, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w30", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w30, #3, #0x10",
            vec![0x9e, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w30", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w0", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w1", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w2", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w3", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w4", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w5", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w6", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w7", 8)],
                memory: vec![],
            },
        ),
(
            "tbz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        ),
(
            "tbz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x36],
            Arm64Fixture {
                registers: vec![("w8", 8)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
