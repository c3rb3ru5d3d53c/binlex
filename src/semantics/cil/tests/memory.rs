use super::common::assert_complete_semantics;

#[test]
fn memory_semantics_regressions_stay_complete() {
    let cases = [
        ("ldfld", vec![0x7b, 0x01, 0x00, 0x00, 0x04]),
        ("ldflda", vec![0x7c, 0x01, 0x00, 0x00, 0x04]),
        ("ldsfld", vec![0x7e, 0x01, 0x00, 0x00, 0x04]),
        ("ldsflda", vec![0x7f, 0x01, 0x00, 0x00, 0x04]),
        ("stfld", vec![0x7d, 0x01, 0x00, 0x00, 0x04]),
        ("stsfld", vec![0x80, 0x01, 0x00, 0x00, 0x04]),
        ("ldelem.i4", vec![0x94]),
        ("ldelem.i", vec![0x97]),
        ("ldelem.i1", vec![0x90]),
        ("ldelem.i2", vec![0x92]),
        ("ldelem.u8", vec![0x96]),
        ("ldelem.r4", vec![0x98]),
        ("stelem.i4", vec![0x9e]),
        ("stelem.i", vec![0x9b]),
        ("stelem.i8", vec![0x9f]),
        ("stelem.r4", vec![0xa0]),
        ("stelem.r8", vec![0xa1]),
        ("ldelema", vec![0x8f, 0x01, 0x00, 0x00, 0x01]),
        ("ldlen", vec![0x8e]),
        ("ldelem.ref", vec![0x9a]),
        ("stelem.ref", vec![0xa2]),
        ("ldind.i4", vec![0x4a]),
        ("ldind.i", vec![0x4d]),
        ("ldind.i1", vec![0x46]),
        ("ldind.i2", vec![0x48]),
        ("stind.i4", vec![0x54]),
        ("ldobj", vec![0x71, 0x01, 0x00, 0x00, 0x01]),
        ("stobj", vec![0x81, 0x01, 0x00, 0x00, 0x01]),
        ("cpblk", vec![0xfe, 0x17]),
        ("initblk", vec![0xfe, 0x18]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, &bytes);
    }
}
