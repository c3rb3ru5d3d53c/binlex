use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fnstsw_semantics_stay_complete() {
    assert_complete_semantics("fnstsw ax", Architecture::I386, &[0xdf, 0xe0]);
}
