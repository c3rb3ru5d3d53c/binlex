use super::common::assert_complete_semantics;

#[test]
fn runtime_semantics_regressions_stay_complete() {
    let cases = [
        ("arglist", vec![0xfe, 0x00]),
        ("localloc", vec![0xfe, 0x0f]),
        ("ckfinite", vec![0xc3]),
        ("endfinally", vec![0xdc]),
        ("endfilter", vec![0xfe, 0x11]),
        ("rethrow", vec![0xfe, 0x1a]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, &bytes);
    }
}
