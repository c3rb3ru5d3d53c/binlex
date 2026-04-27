use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmaxsw_semantics_stay_complete() {
    assert_complete_semantics(
        "pmaxsw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xee, 0xc1],
    );
}
