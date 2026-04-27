use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fmulp_semantics_stay_complete() {
    assert_complete_semantics("fmulp st(1)", Architecture::I386, &[0xde, 0xc9]);
}
