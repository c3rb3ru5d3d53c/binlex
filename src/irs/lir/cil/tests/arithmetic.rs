use super::common::assert_complete_semantics;

#[test]
fn arithmetic_semantics_regressions_stay_complete() {
    let cases = [
        ("add", vec![0x58]),
        ("add.ovf", vec![0xd6]),
        ("sub", vec![0x59]),
        ("sub.ovf", vec![0xda]),
        ("mul", vec![0x5a]),
        ("mul.ovf", vec![0xd8]),
        ("div", vec![0x5b]),
        ("rem.un", vec![0x5e]),
        ("and", vec![0x5f]),
        ("or", vec![0x60]),
        ("xor", vec![0x61]),
        ("shl", vec![0x62]),
        ("shr.un", vec![0x64]),
        ("neg", vec![0x65]),
        ("not", vec![0x66]),
        ("ceq", vec![0xfe, 0x01]),
        ("cgt", vec![0xfe, 0x02]),
        ("clt.un", vec![0xfe, 0x05]),
        ("conv.i4", vec![0x69]),
        ("conv.i", vec![0xd3]),
        ("conv.ovf.i4", vec![0xb7]),
        ("conv.r.un", vec![0x76]),
        ("conv.r4", vec![0x6b]),
        ("conv.r8", vec![0x6c]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, &bytes);
    }
}
