use super::common::lift_instruction_to_llvm;

#[test]
fn cil_semantics_lower_to_llvm() {
    let cases = [
        ("ldlen", vec![0x8e]),
        ("newarr", vec![0x8d, 0x01, 0x00, 0x00, 0x01]),
        ("callvirt", vec![0x6f, 0x01, 0x00, 0x00, 0x0a]),
    ];

    for (name, bytes) in cases {
        let ir = lift_instruction_to_llvm(name, &bytes);
        assert!(ir.contains("define void @instruction_0()"));
        assert!(ir.contains("ret void"));
    }
}
