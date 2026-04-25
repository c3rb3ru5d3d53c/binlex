use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn integer_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "add x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0x8b],
            Arm64Fixture {
                registers: vec![("x1", 0x7fff_ffff_ffff_ffff), ("x2", 1)],
                memory: vec![],
            },
        ),
        (
            "sub x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0xcb],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 3)],
                memory: vec![],
            },
        ),
        (
            "and x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0x8a],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_f0f0_f0f0_f0f0), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
                memory: vec![],
            },
        ),
        (
            "orr x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_0000_f0f0_0000), ("x2", 0x0000_0ff0_0000_0ff0)],
                memory: vec![],
            },
        ),
        (
            "eor x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0xca],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_0000_ffff_0000), ("x2", 0x00ff_00ff_00ff_00ff)],
                memory: vec![],
            },
        ),
        (
            "lsl x0, x1, #3",
            vec![0x20, 0xf0, 0x7d, 0xd3],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "lsr x0, x1, #3",
            vec![0x20, 0xfc, 0x43, 0xd3],
            Arm64Fixture {
                registers: vec![("x1", 0xf123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "asr x0, x1, #3",
            vec![0x20, 0xfc, 0x43, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0xf123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "ror x0, x1, #8",
            vec![0x20, 0x20, 0xc1, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "movz x0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movn x0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movk x0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
        (
            "neg x0, x1",
            vec![0xe0, 0x03, 0x01, 0xcb],
            Arm64Fixture {
                registers: vec![("x1", 5)],
                memory: vec![],
            },
        ),
        (
            "bic x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0x8a],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_0000_ffff_0000), ("x2", 0x00ff_00ff_00ff_00ff)],
                memory: vec![],
            },
        ),
        (
            "eon x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0xca],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_0000_f0f0_0000), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
                memory: vec![],
            },
        ),
        (
            "orn x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_0000_f0f0_0000), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
                memory: vec![],
            },
        ),
        (
            "mvn x0, x1",
            vec![0xe0, 0x03, 0x21, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0x00ff_00ff_00ff_00ff)],
                memory: vec![],
            },
        ),
        (
            "sxtw x0, w1",
            vec![0x20, 0x7c, 0x40, 0x93],
            Arm64Fixture {
                registers: vec![("w1", 0x8000_0001)],
                memory: vec![],
            },
        ),
        (
            "sxtb x0, w1",
            vec![0x20, 0x1c, 0x40, 0x93],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_0081)],
                memory: vec![],
            },
        ),
        (
            "sxth x0, w1",
            vec![0x20, 0x3c, 0x40, 0x93],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_8001)],
                memory: vec![],
            },
        ),
        (
            "mov x0, x1",
            vec![0xe0, 0x03, 0x01, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
        (
            "uxtb w0, w1",
            vec![0x20, 0x1c, 0x00, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_56ab)],
                memory: vec![],
            },
        ),
        (
            "uxth w0, w1",
            vec![0x20, 0x3c, 0x00, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_abcd)],
                memory: vec![],
            },
        ),
        (
            "clz x0, x1",
            vec![0x20, 0x10, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0000_0000_00f0)],
                memory: vec![],
            },
        ),
        (
            "rev x0, x1",
            vec![0x20, 0x0c, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "add w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x0b],
            Arm64Fixture {
                registers: vec![("w1", 0x7fff_ffff), ("w2", 1)],
                memory: vec![],
            },
        ),
        (
            "sub w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x4b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 3)],
                memory: vec![],
            },
        ),
        (
            "and w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x0a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_f0f0), ("w2", 0x0ff0_0ff0)],
                memory: vec![],
            },
        ),
        (
            "orr w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_0000), ("w2", 0x0000_0ff0)],
                memory: vec![],
            },
        ),
        (
            "eor w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x4a],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_0000), ("w2", 0x00ff_00ff)],
                memory: vec![],
            },
        ),
        (
            "bic w0, w1, w2",
            vec![0x20, 0x00, 0x22, 0x0a],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_0000), ("w2", 0x00ff_00ff)],
                memory: vec![],
            },
        ),
        (
            "orn w0, w1, w2",
            vec![0x20, 0x00, 0x22, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_0000), ("w2", 0x0ff0_0ff0)],
                memory: vec![],
            },
        ),
        (
            "mvn w0, w1",
            vec![0xe0, 0x03, 0x21, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0x00ff_00ff)],
                memory: vec![],
            },
        ),
        (
            "neg w0, w1",
            vec![0xe0, 0x03, 0x01, 0x4b],
            Arm64Fixture {
                registers: vec![("w1", 5)],
                memory: vec![],
            },
        ),
        (
            "lsl w0, w1, #3",
            vec![0x20, 0x70, 0x1d, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        ),
        (
            "lsr w0, w1, #3",
            vec![0x20, 0x7c, 0x03, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0xf234_5678)],
                memory: vec![],
            },
        ),
        (
            "asr w0, w1, #3",
            vec![0x20, 0x7c, 0x03, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0xf234_5678)],
                memory: vec![],
            },
        ),
        (
            "mov w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x52],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "mov w0, #-4661",
            vec![0x80, 0x46, 0x82, 0x12],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movk w0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x72],
            Arm64Fixture {
                registers: vec![("w0", 0x0000_ffff)],
                memory: vec![],
            },
        ),
        (
            "mov w0, w1",
            vec![0xe0, 0x03, 0x01, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        ),
        (
            "clz w0, w1",
            vec![0x20, 0x10, 0xc0, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_00f0)],
                memory: vec![],
            },
        ),
        (
            "rev w0, w1",
            vec![0x20, 0x08, 0xc0, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        ),
        (
            "ror w0, w1, #8",
            vec![0x20, 0x20, 0x81, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        ),
        (
            "eon w0, w1, w2",
            vec![0x20, 0x00, 0x22, 0x4a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_0000), ("w2", 0x0ff0_0ff0)],
                memory: vec![],
            },
        ),
        (
            "mov x0, #0x1234",
            vec![0x80, 0x46, 0x82, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "mov x0, #-4661",
            vec![0x80, 0x46, 0x82, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movk x0, #0x1234",
            vec![0x80, 0x46, 0x82, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
        (
            "movk w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x72],
            Arm64Fixture {
                registers: vec![("w0", 0x0000_ffff)],
                memory: vec![],
            },
        ),
        (
            "movz x0, #0x1234, lsl #48",
            vec![0x80, 0x46, 0xe2, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movn x0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movn w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x12],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movz w0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x52],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "rev16 x0, x1",
            vec![0x20, 0x04, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x1122_3344_5566_7788)],
                memory: vec![],
            },
        ),
        (
            "rev32 x0, x1",
            vec![0x20, 0x08, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x1122_3344_5566_7788)],
                memory: vec![],
            },
        ),
        (
            "extr w8, w0, w8, #1",
            vec![0x08, 0x04, 0x88, 0x13],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_5678), ("w8", 0x89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "rev16 w0, w1",
            vec![0x20, 0x04, 0xc0, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x1122_3344)],
                memory: vec![],
            },
        ),
        (
            "ubfx x0, x1, #4, #8",
            vec![0x20, 0x2c, 0x44, 0xd3],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "sbfx x0, x1, #4, #8",
            vec![0x20, 0x2c, 0x44, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0000_0000_0ff0)],
                memory: vec![],
            },
        ),
        (
            "ubfx w0, w1, #4, #8",
            vec![0x20, 0x2c, 0x04, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "ubfiz x0, x1, #4, #8",
            vec![0x20, 0x1c, 0x7c, 0xd3],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "bfxil x0, x1, #4, #8",
            vec![0x20, 0x2c, 0x44, 0xb3],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_0000_ffff_0000), ("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "bfi x0, x1, #4, #8",
            vec![0x20, 0x1c, 0x7c, 0xb3],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_0000_ffff_0000), ("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "sbfiz x0, x1, #4, #8",
            vec![0x20, 0x1c, 0x7c, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0000_0000_00f1)],
                memory: vec![],
            },
        ),
        (
            "sbfx w0, w1, #4, #8",
            vec![0x20, 0x2c, 0x04, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_0ff0)],
                memory: vec![],
            },
        ),
        (
            "movk x0, #0x1234, lsl #48",
            vec![0x80, 0x46, 0xe2, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0x0000_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
        (
            "movn w0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x12],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "ubfiz w0, w1, #4, #8",
            vec![0x20, 0x1c, 0x1c, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "bfxil w0, w1, #4, #8",
            vec![0x20, 0x2c, 0x04, 0x33],
            Arm64Fixture {
                registers: vec![("w0", 0xffff_0000), ("w1", 0x89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "bfi w0, w1, #4, #8",
            vec![0x20, 0x1c, 0x1c, 0x33],
            Arm64Fixture {
                registers: vec![("w0", 0xffff_0000), ("w1", 0x89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "sbfiz w0, w1, #4, #8",
            vec![0x20, 0x1c, 0x1c, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_00f1)],
                memory: vec![],
            },
        ),
        (
            "movz x0, #0x1234, lsl #32",
            vec![0x80, 0x46, 0xc2, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movn x0, #0x1234, lsl #32",
            vec![0x80, 0x46, 0xc2, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "mov w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x52],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movk x0, #0x1234, lsl #32",
            vec![0x80, 0x46, 0xc2, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0x0000_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
        (
            "mul x0, x1, x2",
            vec![0x20, 0x7c, 0x02, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 6)],
                memory: vec![],
            },
        ),
        (
            "mul w0, w1, w2",
            vec![0x20, 0x7c, 0x02, 0x1b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6)],
                memory: vec![],
            },
        ),
        (
            "udiv x0, x1, x2",
            vec![0x20, 0x08, 0xc2, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 100), ("x2", 5)],
                memory: vec![],
            },
        ),
        (
            "sdiv x0, x1, x2",
            vec![0x20, 0x0c, 0xc2, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_ffff_ffff_ff9c), ("x2", 5)],
                memory: vec![],
            },
        ),
        (
            "rbit x0, x1",
            vec![0x20, 0x00, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
        (
            "rbit w0, w1",
            vec![0x20, 0x00, 0xc0, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        ),
        (
            "sxtb w0, w1",
            vec![0x20, 0x1c, 0x00, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_0081)],
                memory: vec![],
            },
        ),
        (
            "sxth w0, w1",
            vec![0x20, 0x3c, 0x00, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_8001)],
                memory: vec![],
            },
        ),
        (
            "madd x0, x1, x2, x3",
            vec![0x20, 0x0c, 0x02, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 6), ("x3", 5)],
                memory: vec![],
            },
        ),
        (
            "msub x0, x1, x2, x3",
            vec![0x20, 0x8c, 0x02, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 6), ("x3", 100)],
                memory: vec![],
            },
        ),
        (
            "madd w0, w1, w2, w3",
            vec![0x20, 0x0c, 0x02, 0x1b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("w3", 5)],
                memory: vec![],
            },
        ),
        (
            "msub w0, w1, w2, w3",
            vec![0x20, 0x8c, 0x02, 0x1b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("w3", 100)],
                memory: vec![],
            },
        ),
        (
            "mneg x0, x1, x2",
            vec![0x20, 0xfc, 0x02, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 6)],
                memory: vec![],
            },
        ),
        (
            "mneg w0, w1, w2",
            vec![0x20, 0xfc, 0x02, 0x1b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6)],
                memory: vec![],
            },
        ),
        (
            "udiv w0, w1, w2",
            vec![0x20, 0x08, 0xc2, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 100), ("w2", 5)],
                memory: vec![],
            },
        ),
        (
            "sdiv w0, w1, w2",
            vec![0x20, 0x0c, 0xc2, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_ff9c), ("w2", 5)],
                memory: vec![],
            },
        ),
        (
            "umulh x0, x1, x2",
            vec![0x20, 0x7c, 0xc2, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_ffff_ffff_ffff), ("x2", 2)],
                memory: vec![],
            },
        ),
        (
            "smulh x0, x1, x2",
            vec![0x20, 0x7c, 0x42, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_ffff_ffff_fffe), ("x2", 3)],
                memory: vec![],
            },
        ),
        (
            "umull x0, w1, w2",
            vec![0x20, 0x7c, 0xa2, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_ffff), ("w2", 2)],
                memory: vec![],
            },
        ),
        (
            "smull x0, w1, w2",
            vec![0x20, 0x7c, 0x22, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_fffe), ("w2", 3)],
                memory: vec![],
            },
        ),
        (
            "umaddl x0, w1, w2, x3",
            vec![0x20, 0x0c, 0xa2, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("x3", 5)],
                memory: vec![],
            },
        ),
        (
            "smaddl x0, w1, w2, x3",
            vec![0x20, 0x0c, 0x22, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_fffe), ("w2", 3), ("x3", 5)],
                memory: vec![],
            },
        ),
        (
            "umsubl x0, w1, w2, x3",
            vec![0x20, 0x8c, 0xa2, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("x3", 100)],
                memory: vec![],
            },
        ),
        (
            "smsubl x0, w1, w2, x3",
            vec![0x20, 0x8c, 0x22, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_fffe), ("w2", 3), ("x3", 100)],
                memory: vec![],
            },
        ),
        (
            "adc x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 5), ("x2", 7), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "sbc x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 10), ("x2", 3), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "bics x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0xea],
            Arm64Fixture {
                registers: vec![
                    ("x1", 0xffff_0000_ffff_0000),
                    ("x2", 0x00ff_00ff_00ff_00ff),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "cmn x0, x1",
            vec![0x1f, 0x00, 0x01, 0xab],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x7fff_ffff_ffff_ffff),
                    ("x1", 1),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "adc w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("w2", 7), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "sbc w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 10), ("w2", 3), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "bics w0, w1, w2",
            vec![0x20, 0x00, 0x22, 0x6a],
            Arm64Fixture {
                registers: vec![
                    ("w1", 0xffff_0000),
                    ("w2", 0x00ff_00ff),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "cmn w0, w1",
            vec![0x1f, 0x00, 0x01, 0x2b],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0x7fff_ffff),
                    ("w1", 1),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "cmp x0, x1",
            vec![0x1f, 0x00, 0x01, 0xeb],
            Arm64Fixture {
                registers: vec![
                    ("x0", 5),
                    ("x1", 7),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "tst x0, x1",
            vec![0x1f, 0x00, 0x01, 0xea],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0xf0f0_0000_f0f0_0000),
                    ("x1", 0x0ff0_0ff0_0ff0_0ff0),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "cmp w0, w1",
            vec![0x1f, 0x00, 0x01, 0x6b],
            Arm64Fixture {
                registers: vec![
                    ("w0", 5),
                    ("w1", 7),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
        (
            "tst w0, w1",
            vec![0x1f, 0x00, 0x01, 0x6a],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0xf0f0_0000),
                    ("w1", 0x0ff0_0ff0),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
