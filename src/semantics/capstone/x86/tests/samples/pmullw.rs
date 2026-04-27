use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmullw_semantics_stay_complete() {
    assert_complete_semantics(
        "pmullw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xd5, 0xc1],
    );
}
