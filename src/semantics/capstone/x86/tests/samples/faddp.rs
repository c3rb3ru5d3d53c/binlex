use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn faddp_semantics_stay_complete() {
    assert_complete_semantics("faddp st(1)", Architecture::I386, &[0xde, 0xc1]);
}
