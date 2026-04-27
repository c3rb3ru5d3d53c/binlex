use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmaxuw_semantics_stay_complete() {
    assert_complete_semantics(
        "pmaxuw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x3e, 0xc1],
    );
}
