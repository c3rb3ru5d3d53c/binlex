use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fsubp_semantics_stay_complete() {
    assert_complete_semantics("fsubp st(1)", Architecture::I386, &[0xde, 0xe9]);
}
