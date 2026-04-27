use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmaxsd_semantics_stay_complete() {
    assert_complete_semantics(
        "pmaxsd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x3d, 0xc1],
    );
}
