use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmovzxwd_semantics_stay_complete() {
    assert_complete_semantics(
        "pmovzxwd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x33, 0xc1],
    );
}
