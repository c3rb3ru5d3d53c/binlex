use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn control_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "csel x0, x1, x2, eq",
            vec![0x20, 0x00, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "cset x0, eq",
            vec![0xe0, 0x17, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, eq",
            vec![0x20, 0x04, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, eq",
            vec![0x20, 0x14, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, eq",
            vec![0xe0, 0x13, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, eq",
            vec![0x20, 0x00, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, eq",
            vec![0x20, 0x04, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, eq",
            vec![0x20, 0x14, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, eq",
            vec![0x20, 0x00, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "cset w0, eq",
            vec![0xe0, 0x17, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, eq",
            vec![0x20, 0x04, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, eq",
            vec![0x20, 0x14, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, eq",
            vec![0xe0, 0x13, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, eq",
            vec![0x20, 0x00, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, eq",
            vec![0x20, 0x04, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, eq",
            vec![0x20, 0x14, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, eq",
            vec![0x00, 0x00, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, eq",
            vec![0x00, 0x08, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, eq",
            vec![0x00, 0x00, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, eq",
            vec![0x00, 0x08, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, eq",
            vec![0x00, 0x00, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, eq",
            vec![0x00, 0x08, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, eq",
            vec![0x00, 0x00, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, eq",
            vec![0x00, 0x08, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, eq",
            vec![0x0a, 0x00, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, eq",
            vec![0x0a, 0x08, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, eq",
            vec![0x0a, 0x00, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, eq",
            vec![0x0a, 0x08, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, eq",
            vec![0x0a, 0x00, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, eq",
            vec![0x0a, 0x08, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, eq",
            vec![0x0a, 0x00, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, eq",
            vec![0x0a, 0x08, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "csel x0, x1, x2, ne",
            vec![0x20, 0x10, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cset x0, ne",
            vec![0xe0, 0x07, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, mi",
            vec![0x20, 0x44, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("n", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, pl",
            vec![0x20, 0x50, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("n", 0)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, ne",
            vec![0x20, 0x10, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cset w0, ne",
            vec![0xe0, 0x07, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, mi",
            vec![0x20, 0x44, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("n", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, pl",
            vec![0x20, 0x50, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("n", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, ne",
            vec![0xe0, 0x03, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, mi",
            vec![0x20, 0x44, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("n", 1)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, ne",
            vec![0x20, 0x04, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, mi",
            vec![0x20, 0x54, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("n", 1)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, ne",
            vec![0xe0, 0x03, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, mi",
            vec![0x20, 0x44, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("n", 1)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, ne",
            vec![0x20, 0x04, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, mi",
            vec![0x20, 0x54, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("n", 1)],
                memory: vec![],
            },
        ),
        (
            "csel x0, x1, x2, gt",
            vec![0x20, 0xc0, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cset x0, le",
            vec![0xe0, 0xc7, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, gt",
            vec![0x20, 0xc4, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, le",
            vec![0x20, 0xd0, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, gt",
            vec![0x20, 0xc0, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cset w0, le",
            vec![0xe0, 0xc7, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, gt",
            vec![0x20, 0xc4, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, le",
            vec![0x20, 0xd0, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csel x0, x1, x2, ge",
            vec![0x20, 0xa0, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cset x0, lt",
            vec![0xe0, 0xa7, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, ge",
            vec![0x20, 0xa4, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, lt",
            vec![0x20, 0xb0, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, ge",
            vec![0x20, 0xa0, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cset w0, lt",
            vec![0xe0, 0xa7, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, ge",
            vec![0x20, 0xa4, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, lt",
            vec![0x20, 0xb0, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csel x0, x1, x2, hi",
            vec![0x20, 0x80, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cset x0, ls",
            vec![0xe0, 0x87, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, hi",
            vec![0x20, 0x84, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, ls",
            vec![0x20, 0x90, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, hi",
            vec![0x20, 0x80, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cset w0, ls",
            vec![0xe0, 0x87, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, hi",
            vec![0x20, 0x84, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, ls",
            vec![0x20, 0x90, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csel x0, x1, x2, vs",
            vec![0x20, 0x60, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "cset x0, vc",
            vec![0xe0, 0x67, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, vs",
            vec![0x20, 0x64, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, vc",
            vec![0x20, 0x70, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, vs",
            vec![0x20, 0x60, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "cset w0, vc",
            vec![0xe0, 0x67, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, vs",
            vec![0x20, 0x64, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, vc",
            vec![0x20, 0x70, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csel x0, x1, x2, hs",
            vec![0x20, 0x20, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("c", 1)],
                memory: vec![],
            },
        ),
        (
            "cset x0, lo",
            vec![0xe0, 0x27, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc x0, x1, x2, hs",
            vec![0x20, 0x24, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("c", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv x0, x1, x2, lo",
            vec![0x20, 0x30, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("c", 0)],
                memory: vec![],
            },
        ),
        (
            "csel w0, w1, w2, hs",
            vec![0x20, 0x20, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("c", 1)],
                memory: vec![],
            },
        ),
        (
            "cset w0, lo",
            vec![0xe0, 0x27, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
        (
            "csinc w0, w1, w2, hs",
            vec![0x20, 0x24, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("c", 1)],
                memory: vec![],
            },
        ),
        (
            "csinv w0, w1, w2, lo",
            vec![0x20, 0x30, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("c", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, gt",
            vec![0xe0, 0xd3, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, le",
            vec![0x20, 0xd4, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, gt",
            vec![0x20, 0xd4, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, le",
            vec![0x20, 0xc4, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, gt",
            vec![0xe0, 0xd3, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, le",
            vec![0x20, 0xd4, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, gt",
            vec![0x20, 0xd4, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, le",
            vec![0x20, 0xc4, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, hi",
            vec![0xe0, 0x93, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, ls",
            vec![0x20, 0x94, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, hi",
            vec![0x20, 0x94, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, ls",
            vec![0x20, 0x84, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, hi",
            vec![0xe0, 0x93, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, ls",
            vec![0x20, 0x94, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, hi",
            vec![0x20, 0x94, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, ls",
            vec![0x20, 0x84, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, vs",
            vec![0xe0, 0x73, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, vc",
            vec![0x20, 0x74, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, vs",
            vec![0x20, 0x74, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, vc",
            vec![0x20, 0x64, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, vs",
            vec![0xe0, 0x73, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, vc",
            vec![0x20, 0x74, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, vs",
            vec![0x20, 0x74, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("v", 1)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, vc",
            vec![0x20, 0x64, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, ge",
            vec![0xe0, 0xb3, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, lt",
            vec![0x20, 0xb4, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, ge",
            vec![0x20, 0xb4, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, lt",
            vec![0x20, 0xa4, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, ge",
            vec![0xe0, 0xb3, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, lt",
            vec![0x20, 0xb4, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, ge",
            vec![0x20, 0xb4, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, lt",
            vec![0x20, 0xa4, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm x0, hs",
            vec![0xe0, 0x33, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
        (
            "csneg x0, x1, x2, lo",
            vec![0x20, 0x34, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("c", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc x0, x1, hs",
            vec![0x20, 0x34, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("c", 1)],
                memory: vec![],
            },
        ),
        (
            "cneg x0, x1, lo",
            vec![0x20, 0x24, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("c", 0)],
                memory: vec![],
            },
        ),
        (
            "csetm w0, hs",
            vec![0xe0, 0x33, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
        (
            "csneg w0, w1, w2, lo",
            vec![0x20, 0x34, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("c", 0)],
                memory: vec![],
            },
        ),
        (
            "cinc w0, w1, hs",
            vec![0x20, 0x34, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("c", 1)],
                memory: vec![],
            },
        ),
        (
            "cneg w0, w1, lo",
            vec![0x20, 0x24, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("c", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, gt",
            vec![0x00, 0xc0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, gt",
            vec![0x00, 0xc8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, gt",
            vec![0x00, 0xc0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, gt",
            vec![0x00, 0xc8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, gt",
            vec![0x00, 0xc0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, gt",
            vec![0x00, 0xc8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, gt",
            vec![0x00, 0xc0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, gt",
            vec![0x00, 0xc8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, gt",
            vec![0x0a, 0xc0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, gt",
            vec![0x0a, 0xc8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, gt",
            vec![0x0a, 0xc0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, gt",
            vec![0x0a, 0xc8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, gt",
            vec![0x0a, 0xc0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, gt",
            vec![0x0a, 0xc8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, gt",
            vec![0x0a, 0xc0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, gt",
            vec![0x0a, 0xc8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, hi",
            vec![0x00, 0x80, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, hi",
            vec![0x00, 0x88, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, hi",
            vec![0x00, 0x80, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, hi",
            vec![0x00, 0x88, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, hi",
            vec![0x00, 0x80, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, hi",
            vec![0x00, 0x88, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, hi",
            vec![0x00, 0x80, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, hi",
            vec![0x00, 0x88, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, hi",
            vec![0x0a, 0x80, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, hi",
            vec![0x0a, 0x88, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, hi",
            vec![0x0a, 0x80, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, hi",
            vec![0x0a, 0x88, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, hi",
            vec![0x0a, 0x80, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, hi",
            vec![0x0a, 0x88, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, hi",
            vec![0x0a, 0x80, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, hi",
            vec![0x0a, 0x88, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, vs",
            vec![0x00, 0x60, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, vs",
            vec![0x00, 0x68, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, vs",
            vec![0x00, 0x60, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, vs",
            vec![0x00, 0x68, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, vs",
            vec![0x00, 0x60, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, vs",
            vec![0x00, 0x68, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, vs",
            vec![0x00, 0x60, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, vs",
            vec![0x00, 0x68, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, vs",
            vec![0x0a, 0x60, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, vs",
            vec![0x0a, 0x68, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, vs",
            vec![0x0a, 0x60, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, vs",
            vec![0x0a, 0x68, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, vs",
            vec![0x0a, 0x60, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, vs",
            vec![0x0a, 0x68, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, vs",
            vec![0x0a, 0x60, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, vs",
            vec![0x0a, 0x68, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, ge",
            vec![0x00, 0xa0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, ge",
            vec![0x00, 0xa8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, ge",
            vec![0x00, 0xa0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, ge",
            vec![0x00, 0xa8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, ge",
            vec![0x00, 0xa0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, ge",
            vec![0x00, 0xa8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, ge",
            vec![0x00, 0xa0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, ge",
            vec![0x00, 0xa8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, ge",
            vec![0x0a, 0xa0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, ge",
            vec![0x0a, 0xa8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, ge",
            vec![0x0a, 0xa0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, ge",
            vec![0x0a, 0xa8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, ge",
            vec![0x0a, 0xa0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, ge",
            vec![0x0a, 0xa8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, ge",
            vec![0x0a, 0xa0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, ge",
            vec![0x0a, 0xa8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, lt",
            vec![0x00, 0xb0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, lt",
            vec![0x00, 0xb8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, lt",
            vec![0x00, 0xb0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, lt",
            vec![0x00, 0xb8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, lt",
            vec![0x00, 0xb0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, lt",
            vec![0x00, 0xb8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, lt",
            vec![0x00, 0xb0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, lt",
            vec![0x00, 0xb8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, lt",
            vec![0x0a, 0xb0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, lt",
            vec![0x0a, 0xb8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, lt",
            vec![0x0a, 0xb0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, lt",
            vec![0x0a, 0xb8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, lt",
            vec![0x0a, 0xb0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, lt",
            vec![0x0a, 0xb8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, lt",
            vec![0x0a, 0xb0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, lt",
            vec![0x0a, 0xb8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, le",
            vec![0x00, 0xd0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, le",
            vec![0x00, 0xd8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, le",
            vec![0x00, 0xd0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, le",
            vec![0x00, 0xd8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, le",
            vec![0x00, 0xd0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, le",
            vec![0x00, 0xd8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, le",
            vec![0x00, 0xd0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, le",
            vec![0x00, 0xd8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, le",
            vec![0x0a, 0xd0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, le",
            vec![0x0a, 0xd8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, le",
            vec![0x0a, 0xd0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, le",
            vec![0x0a, 0xd8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, le",
            vec![0x0a, 0xd0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, le",
            vec![0x0a, 0xd8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, le",
            vec![0x0a, 0xd0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, le",
            vec![0x0a, 0xd8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, hs",
            vec![0x00, 0x20, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, hs",
            vec![0x00, 0x28, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, hs",
            vec![0x00, 0x20, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, hs",
            vec![0x00, 0x28, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, hs",
            vec![0x00, 0x20, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, hs",
            vec![0x00, 0x28, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, hs",
            vec![0x00, 0x20, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, hs",
            vec![0x00, 0x28, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, hs",
            vec![0x0a, 0x20, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, hs",
            vec![0x0a, 0x28, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, hs",
            vec![0x0a, 0x20, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, hs",
            vec![0x0a, 0x28, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, hs",
            vec![0x0a, 0x20, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, hs",
            vec![0x0a, 0x28, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, hs",
            vec![0x0a, 0x20, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, hs",
            vec![0x0a, 0x28, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, lo",
            vec![0x00, 0x30, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, lo",
            vec![0x00, 0x38, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, lo",
            vec![0x00, 0x30, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, lo",
            vec![0x00, 0x38, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, lo",
            vec![0x00, 0x30, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, lo",
            vec![0x00, 0x38, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, lo",
            vec![0x00, 0x30, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, lo",
            vec![0x00, 0x38, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, lo",
            vec![0x0a, 0x30, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, lo",
            vec![0x0a, 0x38, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, lo",
            vec![0x0a, 0x30, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, lo",
            vec![0x0a, 0x38, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, lo",
            vec![0x0a, 0x30, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, lo",
            vec![0x0a, 0x38, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, lo",
            vec![0x0a, 0x30, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, lo",
            vec![0x0a, 0x38, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, vc",
            vec![0x00, 0x70, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, vc",
            vec![0x00, 0x78, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, vc",
            vec![0x00, 0x70, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, vc",
            vec![0x00, 0x78, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, vc",
            vec![0x00, 0x70, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, vc",
            vec![0x00, 0x78, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, vc",
            vec![0x00, 0x70, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, vc",
            vec![0x00, 0x78, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, vc",
            vec![0x0a, 0x70, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, vc",
            vec![0x0a, 0x78, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, vc",
            vec![0x0a, 0x70, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, vc",
            vec![0x0a, 0x78, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, vc",
            vec![0x0a, 0x70, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, vc",
            vec![0x0a, 0x78, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, vc",
            vec![0x0a, 0x70, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, vc",
            vec![0x0a, 0x78, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("v", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, mi",
            vec![0x00, 0x40, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, mi",
            vec![0x00, 0x48, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, mi",
            vec![0x00, 0x40, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, mi",
            vec![0x00, 0x48, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, mi",
            vec![0x00, 0x40, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, mi",
            vec![0x00, 0x48, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, mi",
            vec![0x00, 0x40, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, mi",
            vec![0x00, 0x48, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, mi",
            vec![0x0a, 0x40, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, mi",
            vec![0x0a, 0x48, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, mi",
            vec![0x0a, 0x40, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, mi",
            vec![0x0a, 0x48, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, mi",
            vec![0x0a, 0x40, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, mi",
            vec![0x0a, 0x48, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, mi",
            vec![0x0a, 0x40, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, mi",
            vec![0x0a, 0x48, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, pl",
            vec![0x00, 0x50, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, pl",
            vec![0x00, 0x58, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, pl",
            vec![0x00, 0x50, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, pl",
            vec![0x00, 0x58, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, pl",
            vec![0x00, 0x50, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, pl",
            vec![0x00, 0x58, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, pl",
            vec![0x00, 0x50, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, pl",
            vec![0x00, 0x58, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, pl",
            vec![0x0a, 0x50, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, pl",
            vec![0x0a, 0x58, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, pl",
            vec![0x0a, 0x50, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, pl",
            vec![0x0a, 0x58, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, pl",
            vec![0x0a, 0x50, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, pl",
            vec![0x0a, 0x58, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, pl",
            vec![0x0a, 0x50, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, pl",
            vec![0x0a, 0x58, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, al",
            vec![0x00, 0xe0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, al",
            vec![0x00, 0xe8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, al",
            vec![0x00, 0xe0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, al",
            vec![0x00, 0xe8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, al",
            vec![0x00, 0xe0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, al",
            vec![0x00, 0xe8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, al",
            vec![0x00, 0xe0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, al",
            vec![0x00, 0xe8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, ls",
            vec![0x00, 0x90, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, ls",
            vec![0x00, 0x98, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, ls",
            vec![0x00, 0x90, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, ls",
            vec![0x00, 0x98, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, ls",
            vec![0x00, 0x90, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, ls",
            vec![0x00, 0x98, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, ls",
            vec![0x00, 0x90, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, ls",
            vec![0x00, 0x98, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, ls",
            vec![0x0a, 0x90, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, ls",
            vec![0x0a, 0x98, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, ls",
            vec![0x0a, 0x90, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, ls",
            vec![0x0a, 0x98, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, ls",
            vec![0x0a, 0x90, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, ls",
            vec![0x0a, 0x98, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, ls",
            vec![0x0a, 0x90, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, ls",
            vec![0x0a, 0x98, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, cs",
            vec![0x00, 0x20, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, cs",
            vec![0x00, 0x28, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, cs",
            vec![0x00, 0x20, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, cs",
            vec![0x00, 0x28, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, cs",
            vec![0x00, 0x20, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, cs",
            vec![0x00, 0x28, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, cs",
            vec![0x00, 0x20, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, cs",
            vec![0x00, 0x28, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, cs",
            vec![0x0a, 0x20, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, cs",
            vec![0x0a, 0x28, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, cs",
            vec![0x0a, 0x20, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, cs",
            vec![0x0a, 0x28, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, cs",
            vec![0x0a, 0x20, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, cs",
            vec![0x0a, 0x28, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, cs",
            vec![0x0a, 0x20, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, cs",
            vec![0x0a, 0x28, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, cc",
            vec![0x00, 0x30, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, cc",
            vec![0x00, 0x38, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, cc",
            vec![0x00, 0x30, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, cc",
            vec![0x00, 0x38, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, cc",
            vec![0x00, 0x30, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, cc",
            vec![0x00, 0x38, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, cc",
            vec![0x00, 0x30, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, cc",
            vec![0x00, 0x38, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, cc",
            vec![0x0a, 0x30, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, cc",
            vec![0x0a, 0x38, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, cc",
            vec![0x0a, 0x30, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, cc",
            vec![0x0a, 0x38, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, cc",
            vec![0x0a, 0x30, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, cc",
            vec![0x0a, 0x38, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, cc",
            vec![0x0a, 0x30, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, cc",
            vec![0x0a, 0x38, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, ne",
            vec![0x00, 0x10, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, ne",
            vec![0x00, 0x18, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, ne",
            vec![0x00, 0x10, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, ne",
            vec![0x00, 0x18, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, ne",
            vec![0x00, 0x10, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, ne",
            vec![0x00, 0x18, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, ne",
            vec![0x00, 0x10, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, ne",
            vec![0x00, 0x18, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, ne",
            vec![0x0a, 0x10, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, ne",
            vec![0x0a, 0x18, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, ne",
            vec![0x0a, 0x10, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, ne",
            vec![0x0a, 0x18, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, ne",
            vec![0x0a, 0x10, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, ne",
            vec![0x0a, 0x18, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, ne",
            vec![0x0a, 0x10, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, ne",
            vec![0x0a, 0x18, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("z", 1)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #0, nv",
            vec![0x00, 0xf0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #0, nv",
            vec![0x00, 0xf8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #0, nv",
            vec![0x00, 0xf0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #0, nv",
            vec![0x00, 0xf8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #0, nv",
            vec![0x00, 0xf0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #0, nv",
            vec![0x00, 0xf8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #0, nv",
            vec![0x00, 0xf0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #0, nv",
            vec![0x00, 0xf8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, x1, #10, nv",
            vec![0x0a, 0xf0, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp x0, #1, #10, nv",
            vec![0x0a, 0xf8, 0x41, 0xfa],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, x1, #10, nv",
            vec![0x0a, 0xf0, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn x0, #1, #10, nv",
            vec![0x0a, 0xf8, 0x41, 0xba],
            Arm64Fixture {
                registers: vec![("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, w1, #10, nv",
            vec![0x0a, 0xf0, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmp w0, #1, #10, nv",
            vec![0x0a, 0xf8, 0x41, 0x7a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, w1, #10, nv",
            vec![0x0a, 0xf0, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "ccmn w0, #1, #10, nv",
            vec![0x0a, 0xf8, 0x41, 0x3a],
            Arm64Fixture {
                registers: vec![("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x0", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x0", 1)],
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
            "cbz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w0", 1)],
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
            "tbnz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w0", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
        (
            "b.eq #0x10",
            vec![0x80, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
        (
            "b.eq #0x10",
            vec![0x80, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
        (
            "b.ne #0x10",
            vec![0x81, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
        (
            "b.ne #0x10",
            vec![0x81, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
        (
            "b.mi #0x10",
            vec![0x84, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 1)],
                memory: vec![],
            },
        ),
        (
            "b.mi #0x10",
            vec![0x84, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 0)],
                memory: vec![],
            },
        ),
        (
            "b.pl #0x10",
            vec![0x85, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 0)],
                memory: vec![],
            },
        ),
        (
            "b.pl #0x10",
            vec![0x85, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 1)],
                memory: vec![],
            },
        ),
        (
            "b.gt #0x10",
            vec![0x8c, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.gt #0x10",
            vec![0x8c, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.le #0x10",
            vec![0x8d, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.le #0x10",
            vec![0x8d, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.ge #0x10",
            vec![0x8a, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.ge #0x10",
            vec![0x8a, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.lt #0x10",
            vec![0x8b, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.lt #0x10",
            vec![0x8b, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.hi #0x10",
            vec![0x88, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "b.hi #0x10",
            vec![0x88, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "b.ls #0x10",
            vec![0x89, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "b.ls #0x10",
            vec![0x89, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
        (
            "b.vs #0x10",
            vec![0x86, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
        (
            "b.vs #0x10",
            vec![0x86, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.vc #0x10",
            vec![0x87, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
        (
            "b.vc #0x10",
            vec![0x87, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
        (
            "b.hs #0x10",
            vec![0x82, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
        (
            "b.hs #0x10",
            vec![0x82, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
        (
            "b.lo #0x10",
            vec![0x83, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
        (
            "b.lo #0x10",
            vec![0x83, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
        (
            "b.cs #0x10",
            vec![0x82, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
        (
            "b.cs #0x10",
            vec![0x82, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
        (
            "b.cc #0x10",
            vec![0x83, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
        (
            "b.cc #0x10",
            vec![0x83, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
        (
            "cbz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x1", 1)],
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
            "cbz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w1", 1)],
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
            "tbnz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w1", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w1", 0)],
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
            "tbnz x1, #35, #0x10",
            vec![0x81, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x1, #35, #0x10",
            vec![0x81, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x2", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x2", 1)],
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
            "cbz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w2", 1)],
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
            "cbz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x3", 1)],
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
            "cbz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w3", 1)],
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
            "tbnz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w2", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w2", 0)],
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
            "tbnz x2, #35, #0x10",
            vec![0x82, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x2", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x2, #35, #0x10",
            vec![0x82, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x2", 0)],
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
            "tbnz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w3", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w3", 0)],
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
            "tbnz x3, #35, #0x10",
            vec![0x83, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x3", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x3, #35, #0x10",
            vec![0x83, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x4", 1)],
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
            "cbz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w4", 1)],
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
            "tbnz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w4", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w4", 0)],
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
            "tbnz x4, #35, #0x10",
            vec![0x84, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x4", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x4, #35, #0x10",
            vec![0x84, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x5", 1)],
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
            "cbz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w5", 1)],
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
            "tbnz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w5", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w5", 0)],
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
            "tbnz x5, #35, #0x10",
            vec![0x85, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x5", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x5, #35, #0x10",
            vec![0x85, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x6", 1)],
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
            "cbz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w6", 1)],
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
            "tbnz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w6", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w6", 0)],
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
            "tbnz x6, #35, #0x10",
            vec![0x86, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x6", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x6, #35, #0x10",
            vec![0x86, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x7", 1)],
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
            "cbz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w7", 1)],
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
            "tbnz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w7", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w7", 0)],
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
            "tbnz x7, #35, #0x10",
            vec![0x87, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x7", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x7, #35, #0x10",
            vec![0x87, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x8", 1)],
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
            "cbz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w8", 1)],
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
            "tbnz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w8", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w8", 0)],
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
            "tbnz x8, #35, #0x10",
            vec![0x88, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x8", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x8, #35, #0x10",
            vec![0x88, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x9, #0x10",
            vec![0x89, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x9", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x9, #0x10",
            vec![0x89, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x9", 1)],
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
            "cbz w9, #0x10",
            vec![0x89, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w9", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w9, #0x10",
            vec![0x89, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w9", 1)],
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
            "tbnz w9, #3, #0x10",
            vec![0x89, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w9", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w9, #3, #0x10",
            vec![0x89, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w9", 0)],
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
            "tbnz x9, #35, #0x10",
            vec![0x89, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x9", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x9, #35, #0x10",
            vec![0x89, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x9", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x10, #0x10",
            vec![0x8a, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x10", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x10, #0x10",
            vec![0x8a, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x10", 1)],
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
            "cbz w10, #0x10",
            vec![0x8a, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w10", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w10, #0x10",
            vec![0x8a, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w10", 1)],
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
            "tbnz w10, #3, #0x10",
            vec![0x8a, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w10", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w10, #3, #0x10",
            vec![0x8a, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w10", 0)],
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
            "tbnz x10, #35, #0x10",
            vec![0x8a, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x10", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x10, #35, #0x10",
            vec![0x8a, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x10", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x11, #0x10",
            vec![0x8b, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x11", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x11, #0x10",
            vec![0x8b, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x11", 1)],
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
            "cbz w11, #0x10",
            vec![0x8b, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w11", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w11, #0x10",
            vec![0x8b, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w11", 1)],
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
            "tbnz w11, #3, #0x10",
            vec![0x8b, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w11", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w11, #3, #0x10",
            vec![0x8b, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w11", 0)],
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
            "tbnz x11, #35, #0x10",
            vec![0x8b, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x11", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x11, #35, #0x10",
            vec![0x8b, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x11", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x12, #0x10",
            vec![0x8c, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x12", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x12, #0x10",
            vec![0x8c, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x12", 1)],
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
            "cbz w12, #0x10",
            vec![0x8c, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w12", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w12, #0x10",
            vec![0x8c, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w12", 1)],
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
            "tbnz w12, #3, #0x10",
            vec![0x8c, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w12", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w12, #3, #0x10",
            vec![0x8c, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w12", 0)],
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
            "tbnz x12, #35, #0x10",
            vec![0x8c, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x12", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x12, #35, #0x10",
            vec![0x8c, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x12", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x13, #0x10",
            vec![0x8d, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x13", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x13, #0x10",
            vec![0x8d, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x13", 1)],
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
            "cbz w13, #0x10",
            vec![0x8d, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w13", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w13, #0x10",
            vec![0x8d, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w13", 1)],
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
            "tbnz w13, #3, #0x10",
            vec![0x8d, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w13", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w13, #3, #0x10",
            vec![0x8d, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w13", 0)],
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
            "tbnz x13, #35, #0x10",
            vec![0x8d, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x13", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x13, #35, #0x10",
            vec![0x8d, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x13", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x14, #0x10",
            vec![0x8e, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x14", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x14, #0x10",
            vec![0x8e, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x14", 1)],
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
            "cbz w14, #0x10",
            vec![0x8e, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w14", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w14, #0x10",
            vec![0x8e, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w14", 1)],
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
            "tbnz w14, #3, #0x10",
            vec![0x8e, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w14", 8)],
                memory: vec![],
            },
        ),
        (
            "tbnz w14, #3, #0x10",
            vec![0x8e, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w14", 0)],
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
            "tbnz x14, #35, #0x10",
            vec![0x8e, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x14", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "tbnz x14, #35, #0x10",
            vec![0x8e, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x14", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x15, #0x10",
            vec![0x8f, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x15", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x15, #0x10",
            vec![0x8f, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x15", 1)],
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
            "cbz w15, #0x10",
            vec![0x8f, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w15", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w15, #0x10",
            vec![0x8f, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w15", 1)],
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
            "tbnz w15, #3, #0x10",
            vec![0x8f, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w15", 8)],
                memory: vec![],
            },
        ),
        (
            "cbz x16, #0x10",
            vec![0x90, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x16", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x16, #0x10",
            vec![0x90, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x16", 1)],
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
            "cbz w16, #0x10",
            vec![0x90, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w16", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w16, #0x10",
            vec![0x90, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w16", 1)],
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
            "cbz x17, #0x10",
            vec![0x91, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x17", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x17, #0x10",
            vec![0x91, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x17", 1)],
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
            "cbz w17, #0x10",
            vec![0x91, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w17", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w17, #0x10",
            vec![0x91, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w17", 1)],
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
            "cbz x18, #0x10",
            vec![0x92, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x18", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x18, #0x10",
            vec![0x92, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x18", 1)],
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
            "cbz w18, #0x10",
            vec![0x92, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w18", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w18, #0x10",
            vec![0x92, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w18", 1)],
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
            "cbz x19, #0x10",
            vec![0x93, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x19", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x19, #0x10",
            vec![0x93, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x19", 1)],
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
            "cbz w19, #0x10",
            vec![0x93, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w19", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w19, #0x10",
            vec![0x93, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w19", 1)],
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
            "cbz x20, #0x10",
            vec![0x94, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x20", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x20, #0x10",
            vec![0x94, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x20", 1)],
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
            "cbz w20, #0x10",
            vec![0x94, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w20", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w20, #0x10",
            vec![0x94, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w20", 1)],
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
            "cbz x21, #0x10",
            vec![0x95, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x21", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x21, #0x10",
            vec![0x95, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x21", 1)],
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
            "cbz w21, #0x10",
            vec![0x95, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w21", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w21, #0x10",
            vec![0x95, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w21", 1)],
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
            "cbz x22, #0x10",
            vec![0x96, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x22", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x22, #0x10",
            vec![0x96, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x22", 1)],
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
            "cbz w22, #0x10",
            vec![0x96, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w22", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w22, #0x10",
            vec![0x96, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w22", 1)],
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
            "cbz x23, #0x10",
            vec![0x97, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x23", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x23, #0x10",
            vec![0x97, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x23", 1)],
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
            "cbz w23, #0x10",
            vec![0x97, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w23", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w23, #0x10",
            vec![0x97, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w23", 1)],
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
            "cbz x24, #0x10",
            vec![0x98, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x24", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x24, #0x10",
            vec![0x98, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x24", 1)],
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
            "cbz w24, #0x10",
            vec![0x98, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w24", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w24, #0x10",
            vec![0x98, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w24", 1)],
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
            "cbz x25, #0x10",
            vec![0x99, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x25", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x25, #0x10",
            vec![0x99, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x25", 1)],
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
            "cbz w25, #0x10",
            vec![0x99, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w25", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w25, #0x10",
            vec![0x99, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w25", 1)],
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
            "cbz x26, #0x10",
            vec![0x9a, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x26", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x26, #0x10",
            vec![0x9a, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x26", 1)],
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
            "cbz w26, #0x10",
            vec![0x9a, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w26", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w26, #0x10",
            vec![0x9a, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w26", 1)],
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
            "cbz x27, #0x10",
            vec![0x9b, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x27", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x27, #0x10",
            vec![0x9b, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x27", 1)],
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
            "cbz w27, #0x10",
            vec![0x9b, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w27", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w27, #0x10",
            vec![0x9b, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w27", 1)],
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
            "cbz x28, #0x10",
            vec![0x9c, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x28", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x28, #0x10",
            vec![0x9c, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x28", 1)],
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
            "cbz w28, #0x10",
            vec![0x9c, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w28", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w28, #0x10",
            vec![0x9c, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w28", 1)],
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
            "cbz x29, #0x10",
            vec![0x9d, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x29", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x29, #0x10",
            vec![0x9d, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x29", 1)],
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
            "cbz w29, #0x10",
            vec![0x9d, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w29", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w29, #0x10",
            vec![0x9d, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w29", 1)],
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
            "cbz x30, #0x10",
            vec![0x9e, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x30", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x30, #0x10",
            vec![0x9e, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x30", 1)],
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
            "cbz w30, #0x10",
            vec![0x9e, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w30", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w30, #0x10",
            vec![0x9e, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w30", 1)],
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
            "cbz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x0", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x0, #0x10",
            vec![0x80, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x0", 1)],
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
            "cbz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w0, #0x10",
            vec![0x80, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w0", 1)],
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
            "cbz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x1, #0x10",
            vec![0x81, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x1", 1)],
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
            "cbz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w1, #0x10",
            vec![0x81, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w1", 1)],
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
            "cbz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x2", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x2, #0x10",
            vec![0x82, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x2", 1)],
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
            "cbz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w2, #0x10",
            vec![0x82, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w2", 1)],
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
            "cbz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x3, #0x10",
            vec![0x83, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x3", 1)],
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
            "cbz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w3, #0x10",
            vec![0x83, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w3", 1)],
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
            "cbz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x4, #0x10",
            vec![0x84, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x4", 1)],
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
            "cbz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w4, #0x10",
            vec![0x84, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w4", 1)],
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
            "cbz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x5, #0x10",
            vec![0x85, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x5", 1)],
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
            "cbz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w5, #0x10",
            vec![0x85, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w5", 1)],
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
            "cbz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x6, #0x10",
            vec![0x86, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x6", 1)],
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
            "cbz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w6, #0x10",
            vec![0x86, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w6", 1)],
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
            "cbz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x7, #0x10",
            vec![0x87, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x7", 1)],
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
            "cbz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w7, #0x10",
            vec![0x87, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w7", 1)],
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
            "cbz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz x8, #0x10",
            vec![0x88, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x8", 1)],
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
            "cbz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        ),
        (
            "cbz w8, #0x10",
            vec![0x88, 0x00, 0x00, 0x34],
            Arm64Fixture {
                registers: vec![("w8", 1)],
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
            "cbz x9, #0x10",
            vec![0x89, 0x00, 0x00, 0xb4],
            Arm64Fixture {
                registers: vec![("x9", 0)],
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
