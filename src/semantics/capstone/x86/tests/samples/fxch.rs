use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fxch_semantics_stay_complete() {
    assert_complete_semantics("fxch st(1)", Architecture::I386, &[0xd9, 0xc9]);
}
