use super::common::lift_instruction_to_llvm;

#[test]
fn arm64_semantics_lower_to_llvm() {
    let cases = [
        ("adrp x0, #0", vec![0x00, 0x00, 0x00, 0x90]),
        ("ldrb w0, [x1]", vec![0x20, 0x00, 0x40, 0x39]),
        ("adc x0, x1, x2", vec![0x20, 0x00, 0x02, 0x9a]),
    ];

    for (name, bytes) in cases {
        let ir = lift_instruction_to_llvm(name, &bytes);
        assert!(ir.contains("define void @instruction_0()"));
        assert!(!ir.contains("@binlex_instruction_address"));
    }
}
