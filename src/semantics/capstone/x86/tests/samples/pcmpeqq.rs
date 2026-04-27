use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pcmpeqq_semantics_stay_complete() {
    assert_complete_semantics(
        "vpcmpeqq xmm0, xmm2, xmm1",
        Architecture::AMD64,
        &[0xc4, 0xe2, 0x69, 0x29, 0xc1],
    );
}
