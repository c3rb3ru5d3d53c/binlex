use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmovzxwq_semantics_stay_complete() {
    assert_complete_semantics(
        "pmovzxwq xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x34, 0xc1],
    );
}
