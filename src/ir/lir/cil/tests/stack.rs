use super::common::assert_complete_semantics;

#[test]
fn stack_semantics_regressions_stay_complete() {
    let cases = [
        ("ldc.i4.0", vec![0x16]),
        ("ldc.i4.s", vec![0x1f, 0x7f]),
        (
            "ldc.i8",
            vec![0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
        ("ldc.r4", vec![0x22, 0x00, 0x00, 0x80, 0x3f]),
        (
            "ldc.r8",
            vec![0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f],
        ),
        ("ldnull", vec![0x14]),
        ("dup", vec![0x25]),
        ("pop", vec![0x26]),
        ("ldarg.0", vec![0x02]),
        ("ldarg.s", vec![0x0e, 0x01]),
        ("ldarga.s", vec![0x0f, 0x01]),
        ("ldloc.1", vec![0x07]),
        ("ldloc.s", vec![0x11, 0x01]),
        ("ldloca.s", vec![0x12, 0x01]),
        ("stloc.0", vec![0x0a]),
        ("stloc.1", vec![0x0b]),
        ("stloc.s", vec![0x13, 0x01]),
        ("starg.s", vec![0x10, 0x01]),
        ("ldstr", vec![0x72, 0x01, 0x00, 0x00, 0x70]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, &bytes);
    }
}
