use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmaxud_semantics_stay_complete() {
    assert_complete_semantics(
        "pmaxud xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x3f, 0xc1],
    );
}
