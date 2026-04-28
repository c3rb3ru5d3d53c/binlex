use super::support::lift_instruction_to_llvm;

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

    let fmov_ir = lift_instruction_to_llvm("fmov x0, d1", &[0x20, 0x00, 0x66, 0x9e]);
    assert!(!fmov_ir.contains("@binlex_effect_arm64_fmov"));
    let fmov_rev_ir = lift_instruction_to_llvm("fmov d1, x0", &[0x01, 0x00, 0x67, 0x9e]);
    assert!(!fmov_rev_ir.contains("@binlex_effect_arm64_fmov"));
    let fmov_alt_ir = lift_instruction_to_llvm("fmov x1, d0", &[0x01, 0x00, 0x66, 0x9e]);
    assert!(!fmov_alt_ir.contains("@binlex_effect_arm64_fmov"));
    let fmov_32_ir = lift_instruction_to_llvm("fmov s0, w1", &[0x20, 0x00, 0x27, 0x1e]);
    assert!(!fmov_32_ir.contains("@binlex_effect_arm64_fmov"));
    let fmov_32_rev_ir = lift_instruction_to_llvm("fmov w0, s1", &[0x20, 0x00, 0x26, 0x1e]);
    assert!(!fmov_32_rev_ir.contains("@binlex_effect_arm64_fmov"));
    let fmov_imm_ir = lift_instruction_to_llvm("fmov d0, #1.0", &[0x00, 0x10, 0x6e, 0x1e]);
    assert!(!fmov_imm_ir.contains("@binlex_effect_arm64_fmov"));
    let fmov_imm_s_ir = lift_instruction_to_llvm("fmov s0, #1.0", &[0x00, 0x10, 0x2e, 0x1e]);
    assert!(!fmov_imm_s_ir.contains("@binlex_effect_arm64_fmov"));

    let fmin_ir = lift_instruction_to_llvm("fmin d0, d1, d2", &[0x20, 0x58, 0x62, 0x1e]);
    assert!(!fmin_ir.contains("@binlex_effect_arm64_fmin"));

    let fmax_ir = lift_instruction_to_llvm("fmax d0, d1, d2", &[0x20, 0x48, 0x62, 0x1e]);
    assert!(!fmax_ir.contains("@binlex_effect_arm64_fmax"));

    let fcmp_s_ir = lift_instruction_to_llvm("fcmp s0, s1", &[0x00, 0x20, 0x21, 0x1e]);
    assert!(!fcmp_s_ir.contains("@binlex_effect_arm64_fcmp"));
    let fcmp_d_zero_ir = lift_instruction_to_llvm("fcmp d0, #0.0", &[0x08, 0x20, 0x60, 0x1e]);
    assert!(!fcmp_d_zero_ir.contains("@binlex_effect_arm64_fcmp"));
    let fcmp_s_zero_ir = lift_instruction_to_llvm("fcmp s0, #0.0", &[0x08, 0x20, 0x20, 0x1e]);
    assert!(!fcmp_s_zero_ir.contains("@binlex_effect_arm64_fcmp"));
    let fcmpe_s_ir = lift_instruction_to_llvm("fcmpe s0, s1", &[0x10, 0x20, 0x21, 0x1e]);
    assert!(!fcmpe_s_ir.contains("@binlex_effect_arm64_fcmp"));
    let fcmpe_d_zero_ir = lift_instruction_to_llvm("fcmpe d0, #0.0", &[0x18, 0x20, 0x60, 0x1e]);
    assert!(!fcmpe_d_zero_ir.contains("@binlex_effect_arm64_fcmp"));
    let fcmpe_s_zero_ir = lift_instruction_to_llvm("fcmpe s0, #0.0", &[0x18, 0x20, 0x20, 0x1e]);
    assert!(!fcmpe_s_zero_ir.contains("@binlex_effect_arm64_fcmp"));

    let mrs_ir = lift_instruction_to_llvm("mrs x0, TPIDR_EL0", &[0x40, 0xd0, 0x3b, 0xd5]);
    assert!(!mrs_ir.contains("@binlex_effect_arm64_mrs"));
    let mrs_alt_ir = lift_instruction_to_llvm("mrs x1, TPIDR_EL0", &[0x41, 0xd0, 0x3b, 0xd5]);
    assert!(!mrs_alt_ir.contains("@binlex_effect_arm64_mrs"));
    let mrs_x2_ir = lift_instruction_to_llvm("mrs x2, TPIDR_EL0", &[0x42, 0xd0, 0x3b, 0xd5]);
    assert!(!mrs_x2_ir.contains("@binlex_effect_arm64_mrs"));
    let mrs_fpcr_ir = lift_instruction_to_llvm("mrs x0, FPCR", &[0x00, 0x44, 0x3b, 0xd5]);
    assert!(!mrs_fpcr_ir.contains("@binlex_effect_arm64_mrs"));

    let msr_ir = lift_instruction_to_llvm("msr TPIDR_EL0, x0", &[0x40, 0xd0, 0x1b, 0xd5]);
    assert!(!msr_ir.contains("@binlex_effect_arm64_msr"));
    let msr_alt_ir = lift_instruction_to_llvm("msr TPIDR_EL0, x1", &[0x41, 0xd0, 0x1b, 0xd5]);
    assert!(!msr_alt_ir.contains("@binlex_effect_arm64_msr"));
    let msr_x2_ir = lift_instruction_to_llvm("msr TPIDR_EL0, x2", &[0x42, 0xd0, 0x1b, 0xd5]);
    assert!(!msr_x2_ir.contains("@binlex_effect_arm64_msr"));
    let msr_fpcr_ir = lift_instruction_to_llvm("msr FPCR, x0", &[0x00, 0x44, 0x1b, 0xd5]);
    assert!(!msr_fpcr_ir.contains("@binlex_effect_arm64_msr"));

    let movi_ir = lift_instruction_to_llvm("movi v0.16b, #0", &[0x00, 0xe4, 0x00, 0x4f]);
    assert!(!movi_ir.contains("@binlex_effect_arm64_movi"));
    let movi_alt_ir = lift_instruction_to_llvm("movi v0.8b, #0", &[0x00, 0xe4, 0x00, 0x0f]);
    assert!(!movi_alt_ir.contains("@binlex_effect_arm64_movi"));
    let movi_ff_ir = lift_instruction_to_llvm("movi v0.8b, #255", &[0xe0, 0xe7, 0x07, 0x0f]);
    assert!(!movi_ff_ir.contains("@binlex_effect_arm64_movi"));
    let movi_reg_ir = lift_instruction_to_llvm("movi v1.16b, #255", &[0xe1, 0xe7, 0x07, 0x4f]);
    assert!(!movi_reg_ir.contains("@binlex_effect_arm64_movi"));
    let movi_small_ir = lift_instruction_to_llvm("movi v1.8b, #1", &[0x21, 0xe4, 0x00, 0x0f]);
    assert!(!movi_small_ir.contains("@binlex_effect_arm64_movi"));
    let movi_2d_zero_ir =
        lift_instruction_to_llvm("movi v0.2d, #0000000000000000", &[0x00, 0xe4, 0x00, 0x6f]);
    assert!(!movi_2d_zero_ir.contains("@binlex_effect_arm64_movi"));
    let movi_2d_ff_ir =
        lift_instruction_to_llvm("movi v0.2d, #0xffffffffffffffff", &[0xe0, 0xe7, 0x07, 0x6f]);
    assert!(!movi_2d_ff_ir.contains("@binlex_effect_arm64_movi"));
    let movi_2d_v2_ir =
        lift_instruction_to_llvm("movi v2.2d, #0xffffffffffffffff", &[0xe2, 0xe7, 0x07, 0x6f]);
    assert!(!movi_2d_v2_ir.contains("@binlex_effect_arm64_movi"));
    let movi_2s_ir = lift_instruction_to_llvm("movi v0.2s, #1", &[0x20, 0x04, 0x00, 0x0f]);
    assert!(!movi_2s_ir.contains("@binlex_effect_arm64_movi"));
    let movi_d_ir =
        lift_instruction_to_llvm("movi d0, #0000000000000000", &[0x00, 0xe4, 0x00, 0x2f]);
    assert!(!movi_d_ir.contains("@binlex_effect_arm64_movi"));

    let dup_ir = lift_instruction_to_llvm("dup v0.16b, w1", &[0x20, 0x0c, 0x01, 0x4e]);
    assert!(!dup_ir.contains("@binlex_effect_arm64_dup"));
    let dup_2d_ir = lift_instruction_to_llvm("dup v0.2d, x1", &[0x20, 0x0c, 0x08, 0x4e]);
    assert!(!dup_2d_ir.contains("@binlex_effect_arm64_dup"));

    let cnt_ir = lift_instruction_to_llvm("cnt v0.8b, v1.8b", &[0x20, 0x58, 0x20, 0x0e]);
    assert!(!cnt_ir.contains("@binlex_effect_arm64_cnt"));

    let cmeq_ir = lift_instruction_to_llvm("cmeq v0.2s, v1.2s, v2.2s", &[0x20, 0x8c, 0xa2, 0x2e]);
    assert!(!cmeq_ir.contains("@binlex_effect_arm64_cmeq"));

    let cmhi_ir = lift_instruction_to_llvm("cmhi v0.2s, v1.2s, v2.2s", &[0x20, 0x34, 0xa2, 0x2e]);
    assert!(!cmhi_ir.contains("@binlex_effect_arm64_cmhi"));

    let uzp1_ir = lift_instruction_to_llvm("uzp1 v0.4s, v1.4s, v2.4s", &[0x20, 0x18, 0x82, 0x4e]);
    assert!(!uzp1_ir.contains("@binlex_effect_arm64_uzp1"));

    let addv_ir = lift_instruction_to_llvm("addv s0, v1.4s", &[0x20, 0xb8, 0xb1, 0x4e]);
    assert!(!addv_ir.contains("@binlex_effect_arm64_addv"));

    let uaddlv_ir = lift_instruction_to_llvm("uaddlv h0, v1.8b", &[0x20, 0x38, 0x30, 0x2e]);
    assert!(!uaddlv_ir.contains("@binlex_effect_arm64_uaddlv"));

    let ld1_lane_d_ir = lift_instruction_to_llvm("ld1 {v0.d}[1], [x1]", &[0x20, 0x84, 0x40, 0x4d]);
    assert!(!ld1_lane_d_ir.contains("@binlex_effect_arm64_ld1"));

    let ld1_lane_s_ir = lift_instruction_to_llvm("ld1 {v1.s}[1], [x11]", &[0x61, 0x91, 0x40, 0x0d]);
    assert!(!ld1_lane_s_ir.contains("@binlex_effect_arm64_ld1"));

    let rev64_ir = lift_instruction_to_llvm("rev64 v0.2s, v1.2s", &[0x20, 0x08, 0xa0, 0x0e]);
    assert!(!rev64_ir.contains("@binlex_effect_arm64_rev64"));

    let extr_ir = lift_instruction_to_llvm("extr w8, w0, w8, #1", &[0x08, 0x04, 0x88, 0x13]);
    assert!(!extr_ir.contains("@binlex_effect_arm64_extr"));

    let sshll_ir = lift_instruction_to_llvm("sshll v0.8h, v1.8b, #0", &[0x20, 0xa4, 0x08, 0x0f]);
    assert!(!sshll_ir.contains("@binlex_effect_arm64_sshll"));
    let sshll_wide_ir =
        lift_instruction_to_llvm("sshll v0.4s, v1.4h, #0", &[0x20, 0xa4, 0x10, 0x0f]);
    assert!(!sshll_wide_ir.contains("@binlex_effect_arm64_sshll"));
    let sshll_wide_alt_ir =
        lift_instruction_to_llvm("sshll v1.4s, v0.4h, #0", &[0x01, 0xa4, 0x10, 0x0f]);
    assert!(!sshll_wide_alt_ir.contains("@binlex_effect_arm64_sshll"));
    let sshll_widest_ir =
        lift_instruction_to_llvm("sshll v0.2d, v1.2s, #0", &[0x20, 0xa4, 0x20, 0x0f]);
    assert!(!sshll_widest_ir.contains("@binlex_effect_arm64_sshll"));
}
