use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ccmp_semantics_match_unicorn_transitions() {
    let cases = [
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
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
